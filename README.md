# PowerShell Command Enrichment with ChatGPT Integration

This project integrates ChatGPT into Wazuh to enrich PowerShell commands extracted from security alerts. The script analyzes potentially malicious or benign PowerShell commands and provides detailed insights and recommendations for mitigation or next steps.

## Features

- **PowerShell Command Extraction**: Automatically extracts PowerShell commands from Wazuh alerts.
- **ChatGPT Analysis**: Queries OpenAI's GPT-3.5-turbo model to analyze the extracted commands.
- **Actionable Insights**: Enriches alerts with analysis results, marking commands as malicious or benign, and provides suggestions for response.
- **Wazuh Integration**: Sends enriched alerts back to Wazuh for centralized monitoring and management.

---

## Prerequisites

- **Python 3.x**
- **Wazuh Setup**: Ensure Wazuh is properly installed and configured.
- **OpenAI API Key**: Obtain an API key from OpenAI [here](https://platform.openai.com/).

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Vikas-Chauhan-sudo/Intelligent-investigation.git
   cd Intelligent-investigation/
