# AIOps on RHEL 9 with AAP 2.7: CloudWatch -> SQS -> EDA -> Claude -> Git

Everything is built from scratch: only AAP and one fresh RHEL 9 VM on AWS exist at the start.

## The scenario (manual failure)
`sudo aiops-break` on the VM simulates a botched site migration: web content is copied to `/data/www`
and nginx is pointed at it. The files carry the SELinux label `default_t`, nginx runs as `httpd_t`, so every
request fails with 403. The cause is only provable by correlating **four** log sources:

| CloudWatch log group | What it shows |
|---|---|
| `/aiops/rhel9/messages` | the change (`deploy: change CHG-1042 ... /data/www`) and the probe flipping 200 -> 403 |
| `/aiops/rhel9/nginx-access` | the 403 responses |
| `/aiops/rhel9/nginx-error` | `open() "/data/www/index.html" failed (13: Permission denied)` (this also drives the alarm) |
| `/aiops/rhel9/audit` | `type=AVC ... denied ... scontext=...httpd_t ... tcontext=...default_t` |

## Flow
```
 1  VM breaks (aiops-break)
 2  4 log files -> CloudWatch agent -> 4 CloudWatch log groups
        messages | nginx-access | nginx-error | audit
 3  nginx-error "Permission denied" -> metric filter -> CloudWatch alarm -> SNS -> SQS queue
 4  EDA rulebook reads the queue and STARTS the workflow (it does not read or analyse logs;
    it only passes the alarm details and the list of 4 log-group names)
 5  Workflow node 1 (AAP job) - Claude's root-cause analysis:
      a. job reads the last 15 min from ALL 4 log groups and redacts IPs/secrets
      b. job sends the 4 log excerpts + alarm details to Claude in ONE request
      c. Claude correlates the 4 sources and returns:
           root cause, how the sources fit together, evidence lines (tagged by source),
           confidence, risk, remediation playbook, rollback, verification
      d. policy gate + syntax check on Claude's playbook
 6  Workflow node 2 (AAP job): playbook + incident report -> GitHub branch + pull request
 7  Human reviews/merges the PR -> AAP runs the playbook (limit rhel9-web01) -> fixed
```

### How Claude finds the root cause from the four sources
No single log gives the answer; Claude has to connect them:
- `messages`: a change was made (site content moved to /data/www) and the probe went from 200 to 403.
- `nginx-access`: visitors are getting 403.
- `nginx-error`: nginx cannot open /data/www/index.html (Permission denied).
- `audit`: SELinux denied nginx (httpd_t) access to files labelled default_t.
Together: the move put files in a location with the wrong SELinux label, so nginx is blocked.
The fix Claude writes labels /data for web content (semanage fcontext + restorecon) and reloads nginx.

## 0. What you need
- AWS account where you can create IAM/CloudFormation (admin for the demo), one RHEL 9 EC2 instance (SELinux enforcing, the default), SSH from AAP to it as `ec2-user` (passwordless sudo is the EC2 default).
- Outbound HTTPS from AAP (execution + decision environments) to: `api.anthropic.com`, `api.github.com`, `logs.<region>.amazonaws.com`, `sqs.<region>.amazonaws.com`, `cloudformation.<region>.amazonaws.com`. The VM needs outbound HTTPS to CloudWatch and S3 (to download the agent).
- An Anthropic API key and a GitHub account.
- Region: examples use `ap-south-1`. Change `aws_region` everywhere if different.

## 1. GitHub
1. Create repo **aiops-rhel9-demo** and push this folder to it (AAP Project 1: code).
2. Create repo **aiops-remediations** with an initial commit on `main` (a README is enough). This is where Claude's playbooks land (AAP Project 2 later).
3. Create a fine-grained personal access token limited to `aiops-remediations`: Contents = Read and write, Pull requests = Read and write.

## 2. AAP (Automation Execution)
1. **Credential types** (Infrastructure > Credential Types): create `Anthropic API` and `GitHub token (REST API)` from `credential-types/anthropic.yml` and `github-token.yml` (input config + injector as noted in the files).
2. **Credentials**:
   - Machine: SSH key for `ec2-user` (privilege escalation: sudo).
   - Amazon Web Services: access key of an admin user for now (step 3 creates a least-privilege `LogReaderUser` you can swap in later).
   - Anthropic API: your key. GitHub token: the PAT.
3. **Project**: `aiops-rhel9-demo` (Git URL of repo 1).
4. **Inventory**: group `rhel9_web` with host `rhel9-web01` (`ansible_host` = VM IP, `ansible_user=ec2-user`); see `inventory/hosts.yml`.
5. **Execution environment**: needs boto3, botocore, PyYAML and collections `amazon.aws`, `ansible.posix` (`ee/requirements.*`). Run template 00 to check; build a custom EE only if it fails.
6. **Job templates** (all: project 1, the inventory, **tick "Prompt on launch" for Variables** or workflow variables are ignored):

| Name | Playbook | Credentials | Extra variables |
|---|---|---|---|
| AIOps 00 - Preflight | `playbooks/00_preflight_ee.yml` | none | `aws_region` |
| AIOps 01 - Deploy AWS stack | `playbooks/01_aws_deploy_cfn.yml` | AWS | `aws_region` |
| AIOps 02 - RHEL9 baseline | `playbooks/02_rhel9_baseline.yml` | Machine (become on) | `aws_region` |
| AIOps 03 - Diagnose with Claude | `playbooks/03_diagnose_with_claude.yml` | AWS + Anthropic API | `aws_region` |
| AIOps 04 - Commit remediation to Git | `playbooks/04_commit_to_git.yml` | GitHub token | `github_owner`, `github_repo` |

7. **Workflow template** named exactly `AIOps - Diagnose and Commit Remediation` (the rulebook uses this name; organization Default): node 1 = template 03, on success -> node 2 = template 04. Enable prompt on launch for Variables. Workflow variables: `github_owner`, `github_repo`, `aws_region`. (Values set by `set_stats` in node 1 flow to node 2 automatically.)
8. Run template **00**.

## 3. AWS side
1. Run template **01**. Note the stack outputs.
2. Attach the VM's IAM role: EC2 console > the instance > Actions > Security > Modify IAM role > choose the `InstanceProfileName` from the outputs. (CLI: `aws ec2 associate-iam-instance-profile --instance-id i-... --iam-instance-profile Name=<InstanceProfileName>`)
3. IAM console > Users > `EdaQueueUserName` > Security credentials > create an access key (used by EDA). Optionally the same for `LogReaderUserName` and use it for the AAP AWS credential.

## 4. Baseline the VM
Run template **02**. It installs nginx, the demo site, the CloudWatch agent (shipping the four logs), a probe timer that hits the site every 15 s (and logs the result to syslog), and the scripts `aiops-break` / `aiops-reset`.
Check: CloudWatch > Log groups > the four `/aiops/rhel9/*` groups have events; on the VM `curl -I localhost` returns 200.

## 5. Test the pipeline before EDA (recommended)
On the VM: `sudo aiops-break`. Wait ~2 minutes, then launch the workflow manually from AAP with variables
`{"alarm_name": "manual-test"}`. Open node 1's output: the 4 sources, Claude's root cause, evidence, generated playbook, policy result. Node 2 prints the pull request URL.
Then `sudo aiops-reset` before continuing.

## 6. Automatic path: EDA (Automation Decisions)
1. **Credential type** from `credential-types/eda-aws-sqs.yml`, then a credential with the EdaQueueUser keys (region, queue `aiops-rhel9-alerts`, prefix `/aiops/rhel9`). If extra-vars injection is not available, put the same five values in the activation's Variables instead.
2. **Decision environment**: the default supported one. If the source fails with a missing `aiobotocore`/`botocore`, build one that includes them.
3. **Credential** of type Red Hat Ansible Automation Platform (so EDA can launch the workflow).
4. **Project** (repo 1), then **Rulebook activation**: rulebook `rulebooks/aiops_cloudwatch.yml`, the decision environment, both credentials, log level `debug` for the first run.
   The activation should show "Running" and the log should show it polling the queue.

## 7. Run the demo
1. On the VM: `sudo aiops-break`.
2. About 2-3 minutes later: the alarm goes to ALARM, SNS -> SQS, the rule fires (Rule Audit), the workflow starts.
3. Open node 1 (diagnosis) and node 2 (PR link). The PR contains `remediations/<incident>-nginx.yml` and the incident report.
4. Review and merge the PR. In AAP: add a Project `aiops-remediations` (repo 2), sync, then create/launch a job template "AIOps - Apply remediation": that project, the inventory, Machine credential (become on), **playbook = the new file from the dropdown**, **Limit = rhel9-web01**.
5. Run it. `curl -I localhost` on the VM returns 200 and the alarm returns to OK.
6. Repeat with `sudo aiops-reset` (the rulebook throttles to one run per 15 minutes).

## Guardrails (talk track)
- Logs are redacted (IPs except loopback, `password=`/`token=` style values) before they leave AWS.
- Claude must answer through a forced tool call (strict schema); low confidence or risk -> `escalate_to_human`, nothing is committed.
- `scripts/validate_playbook.py` rejects playbooks that use modules outside the allow-list, weaken SELinux (`setenforce`, permissive, `/etc/selinux/config`, custom policy), use `chmod 777`, reboot, download content, change accounts, or delete outside safe paths. Plus a syntax check.
- Claude's output goes to a pull request, not to the server: a human reviews before anything runs.
- The playbook travels base64-encoded between workflow nodes so its own `{{ }}` is not templated.
- EDA pulls from SQS: AAP does not need to be reachable from the internet.

## Troubleshooting
| Symptom | Check |
|---|---|
| Template 02 fails on the IAM role check | Step 3.2 not done or the instance profile has not propagated (wait a minute). |
| No logs in CloudWatch | `sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status`; `/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log`. |
| Alarm never fires | CloudWatch > Alarms; nginx-error group must show "Permission denied" lines; threshold is 2 per minute. |
| Alarm fires, rule does not | Activation log; SQS console > queue > "Messages available"; credentials; region. |
| Workflow starts but variables are empty | "Prompt on launch > Variables" not ticked on the job templates / workflow. |
| Node 1 "Only N log sources returned data" | Agent not shipping that file yet; widen `lookback_minutes`. |
| Node 1 "Claude API call failed: HTTP 401/403" | Anthropic credential missing on template 03, or egress blocked. |
| Node 2 "GitHub: cannot read ..." | Repo name/owner, token scope, or `main` does not exist. |

## Offline testing
`playbooks/03_diagnose_with_claude.yml -e claude_mock_file=samples/mock_claude_response.json` replays a saved Claude answer, useful to rehearse without an API key. `samples/bad_playbook.yml` shows the policy gate rejecting a "lazy" SELinux fix.
