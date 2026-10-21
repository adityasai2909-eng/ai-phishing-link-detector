# AI Phishing Link Detector

A Streamlit-based web application that helps users assess whether a URL
may be a phishing link. It combines machine-learning predictions,
heuristic URL checks, and an optional VirusTotal lookup to provide
additional context.

> **Disclaimer:** This tool is intended for educational and defensive
> awareness purposes. A prediction is not a guarantee that a website is
> safe or malicious. Avoid entering passwords or sensitive information
> on suspicious websites.

## Features

-   **Machine-learning prediction:** Uses a trained model to classify
    URL patterns.
-   **Heuristic checks:** Highlights potentially suspicious URL
    characteristics.
-   **VirusTotal lookup:** Can provide additional reputation information
    when configured with a valid API key.
-   **Streamlit interface:** Lets users check URLs through a simple web
    interface.
-   **Readable results:** Presents findings to help users make more
    informed decisions.

## Project Structure

``` text
ai-phishing-link-detector/
├── app.py
├── url_features.py
├── phishing_url_model.joblib
├── requirements.txt
├── README.md
├── .gitignore
└── .streamlit/          # Local configuration; do not commit secrets
```

Your local `.venv/` environment should also remain local and should not
be uploaded to GitHub.

## Requirements

-   Python 3.10 or a compatible version supported by the packages in
    `requirements.txt`
-   pip
-   The project files listed above
-   Internet access for optional VirusTotal lookups and deployment

## Run Locally on Windows

1.  Download or clone this repository.

2.  Open Command Prompt or PowerShell in the project folder.

3.  Create and activate a virtual environment:

    ``` powershell
    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    ```

    If PowerShell blocks activation, you can use Command Prompt instead:

    ``` bat
    .venv\Scripts\activate.bat
    ```

4.  Install dependencies:

    ``` bash
    python -m pip install -r requirements.txt
    ```

5.  Start the Streamlit app:

    ``` bash
    python -m streamlit run app.py
    ```

6.  Open the local URL printed in the terminal, usually
    `http://localhost:8501`.

## VirusTotal Configuration (Optional)

If the app supports VirusTotal and requires an API key, store it in
Streamlit secrets rather than hard-coding it into Python code or
committing it to GitHub.

Create `.streamlit/secrets.toml` locally:

``` toml
VIRUSTOTAL_API_KEY = "paste_your_api_key_here"
```

Use the exact secret name expected by your `app.py`. Never publish the
real API key. Keep `.streamlit/secrets.toml` out of Git.

For Streamlit Community Cloud, add the same secret through the app's
**Settings → Secrets** section.

## Deploy on Streamlit Community Cloud

1.  Push the project files to a GitHub repository.
2.  Open [Streamlit Community Cloud](https://share.streamlit.io/).
3.  Select **Create app** and choose the repository and branch.
4.  Set the main file path to `app.py`.
5.  Deploy the app.
6.  Add any required API keys in the app's Secrets settings.

Make sure `app.py`, `url_features.py`, `phishing_url_model.joblib`, and
`requirements.txt` are committed to the selected branch. The model file
must be available at the path expected by the application.

## Important GitHub Safety Notes

Do **not** commit these local or sensitive files:

-   `.venv/`
-   `.streamlit/secrets.toml`
-   API keys, passwords, or tokens
-   `__pycache__/` and `*.pyc`

A simple `.gitignore` can contain:

``` gitignore
.venv/
.streamlit/secrets.toml
__pycache__/
*.py[cod]
.env
```

If `.streamlit/config.toml` contains only non-sensitive display
settings, it may be committed if needed. Review all configuration files
before uploading.

## How It Works

1.  The user submits a URL.
2.  The app extracts URL-related features.
3.  The trained model evaluates the extracted features.
4.  Heuristic checks identify additional warning signs.
5.  If configured, VirusTotal can provide supplementary reputation
    information.
6.  The app displays the results.

The exact checks and output depend on the implementation in `app.py` and
`url_features.py`.

## Limitations

-   Phishing websites and attacker techniques change frequently.
-   Machine-learning models can produce false positives and false
    negatives.
-   A URL that is not flagged is **not guaranteed to be safe**.
-   Third-party reputation results may be unavailable, delayed, or
    incomplete.
-   Do not use this tool as the only basis for security decisions.

## Future Improvements

-   Improve model evaluation with precision, recall, F1-score, and a
    confusion matrix.
-   Add more URL features and regularly review training data.
-   Improve error handling and explain why a URL was flagged.
-   Add automated tests and clearer reporting.
-   Improve the interface and deployment monitoring.

## Educational Purpose

This project demonstrates how machine learning and URL analysis can
support phishing awareness. Test only with URLs you are authorized to
analyze, and do not visit suspicious links unnecessarily.

## Author

**Project:** AI Phishing Link Detector\
**Repository:** `ai-phishing-link-detector`
