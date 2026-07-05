---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: 'bug'
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Environment

**System Information:**

- OS: [e.g., Windows 11 24H2, macOS 15.5]
- Hyperweaver Agent Version: [e.g., 0.1.0]
- Installation Method: [installer/source]
- VirtualBox Version: [e.g., 7.1.x, if relevant]
- Vagrant Version: [e.g., 2.4.x, if relevant]

**Configuration:**

- Port: [e.g., 9420]
- Bind Address: [e.g., 127.0.0.1]
- UI: [embedded/ui.path override/disabled]

## Steps to Reproduce

Steps to reproduce the behavior:

1. Go to '...'
2. Click on '...'
3. Scroll down to '...'
4. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

A clear and concise description of what actually happened.

## Error Messages / Logs

If applicable, add error messages or log excerpts (the agent log lives at `<config dir>/logs/agent.log`):

```text
Paste error messages here
```

## API Requests (if applicable)

**Request:**

```bash
curl "http://127.0.0.1:9420/api/status"
```

**Response:**

```json
{
  "error": "Error details here"
}
```

## Screenshots

If applicable, add screenshots to help explain your problem.

## Additional Context

Add any other context about the problem here.

## Impact Assessment

- [ ] Critical (system unusable, security issue)
- [ ] High (major functionality broken)
- [ ] Medium (functionality impaired)
- [ ] Low (minor issue, workaround available)

**Affected Functionality:**

- [ ] Tray icon / menu
- [ ] Browser launch
- [ ] Web UI serving
- [ ] API endpoints
- [ ] Configuration
- [ ] Logging
- [ ] Documentation

## Resource Understanding

I understand that this project is maintained with limited development resources and that:

- Response times may vary based on current workload and severity
- Critical and high-impact issues receive priority attention
- Detailed bug reports help prioritize and resolve issues more efficiently
