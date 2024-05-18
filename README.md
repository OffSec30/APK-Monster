# APK Monster

APK Monster is a comprehensive tool designed to analyze Android APK files for a wide range of security vulnerabilities. It scans and identifies potential security weaknesses in APK files, helping developers and security professionals ensure their applications are secure.

Made by offsec https://offensivesec.blogspot.com/

## Features

- **String Extraction**: Extracts all strings from XML, ARSC, TXT, and JSON files within the APK.
- **Permission Analysis**: Checks for insecure permissions that may expose the app to unnecessary risks.
- **Cryptography Review**: Identifies weak cryptographic practices within the app’s code.
- **Exported Component Detection**: Highlights exported activities, services, receivers, and providers that could be accessed by malicious entities.
- **Storage Security**: Scans for insecure storage locations used by the app.
- **Communication Security**: Detects the use of insecure communication protocols, such as HTTP.
- **Authentication Practices**: Reviews the app for insecure authentication practices.
- **Code Quality**: Flags poor coding practices that may affect the app’s security.
- **Tampering Protections**: Checks for mechanisms protecting the app from tampering.
- **Reverse Engineering**: Looks for protections against reverse engineering, such as obfuscation.
- **Extraneous Functionality**: Identifies unnecessary or debug functionalities left in the production code.

## Installation

Make sure you have Python installed. Then, install the necessary dependencies:

```sh
pip install androguard termcolor tqdm
```

## Usage

To analyze an APK file, run the script with the path to your APK file and the output file for the results:

```sh
python analyze_apk.py path/to/your.apk path/to/output.txt
```

### Example

```sh
python analyze_apk.py sample.apk results.txt
```

## Output

APK Monster generates a detailed report highlighting each aspect of the APK’s security. The report categorizes issues and provides clear indications of potential vulnerabilities, such as hardcoded secrets, insecure permissions, weak cryptography, exported components, insecure storage, insecure communication, insecure authentication, code quality issues, tampering protections, reverse engineering issues, and extraneous functionality.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or feedback, feel free to reach out.
