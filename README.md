# GitHub Phishing Attack Detector

This project provides tools to detect, analyze, and track phishing attacks propagating through GitHub issues. Currently, there is an ongoing phishing attack using GitHub Actions to request user tokens with certain permissions and then propagate the attack to other repositories.

## Features

- Detection of phishing issues using specific search terms
- Tracking of compromised users
- Analysis of attack propagation over time
- Incremental processing for continuous monitoring
- Automatic updates using GitHub Actions
- Data storage for historical analysis
- Detailed attack reports

## Requirements

- Python 3.6+
- Required libraries:
  - requests

You can install the dependencies with:

```bash
pip install requests
```

## GitHub Token Configuration

The project uses the `GITHUB_TOKEN` environment variable to authenticate with the GitHub API. This helps avoid API rate limits.

To configure the token:

1. Create a GitHub personal token (see instructions below)
2. Set the environment variable:

```bash
# On Linux/macOS
export GITHUB_TOKEN="your_token_here"

# On Windows (CMD)
set GITHUB_TOKEN=your_token_here

# On Windows (PowerShell)
$env:GITHUB_TOKEN="your_token_here"
```

## Using the Phishing Detector

The main script `github_phishing_detector.py` now supports incremental processing, which means it only processes new issues since the last execution.

### Available Options

- `--full`: Process all issues, ignoring the last processing state
- `--pages N`: Process a maximum of N pages of results (default: 200)

### Usage Examples

```bash
# Normal execution (incremental processing)
python github_phishing_detector.py

# Full processing (ignore history)
python github_phishing_detector.py --full

# Limit search to 10 pages
python github_phishing_detector.py --pages 10

# Combine options
python github_phishing_detector.py --full --pages 5
```

## GitHub Actions Configuration

This project includes a GitHub Action that runs the detector every 5 minutes and automatically updates the data. The configuration is in `.github/workflows/phishing-detector.yml`.

To set up the automatic action:

1. Fork this repository
2. Make sure GitHub Actions is enabled in your repository
3. Configure the permissions so that the GitHub Actions token can write to the repository
4. The action will run automatically every 5 minutes

To run the action manually, go to the "Actions" tab in your repository and select "GitHub Phishing Detector" > "Run workflow".

## Data Structure

The data is stored in the `data/` directory:

- `phishing_issues.csv`: Information about all detected issues
- `compromised_users.csv`: List of compromised users and their activity
- `attack_stats.json`: General attack statistics
- `last_run_data.json`: Information about the last execution for incremental processing

## How to Get a GitHub Token

To avoid GitHub API rate limits, it's recommended to use a personal token:

1. Go to your GitHub settings: https://github.com/settings/tokens
2. Click on "Generate new token"
3. Select the "public_repo" scope (read-only)
4. Generate the token and configure it as the `GITHUB_TOKEN` environment variable

## Contributing

If you want to contribute to this project:

1. Add new relevant search terms
2. Improve detection techniques
3. Implement more advanced analysis
4. Report new attack patterns

## Disclaimer

This project is for research and educational purposes only. It does not store sensitive information and only collects public data available through the GitHub API.

## License

MIT 