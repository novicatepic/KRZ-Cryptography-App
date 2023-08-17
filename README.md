# Cryptography Course Project

Create an application that serves as a secure repository for storing confidential documents. The application should allow storage of documents for multiple users, ensuring that access to a specific document is granted only to its owner.

Users authenticate to the system through a two-step process. In the first step, users need to provide their digital certificate received upon creating their account. If the certificate is valid, the user is presented with a form to enter their username and password. Upon successful login, the user can access a list of their documents through a user-friendly interface.

The application enables users to both download existing documents and upload new ones. Each new document is divided into N segments (N≥4, a randomly generated value) before being stored on the file system. Each segment is placed in a different directory to enhance system security and reduce the risk of document theft. It's essential to adequately protect the confidentiality and integrity of each segment, ensuring that only the user to whom the document belongs can access and view its content. The application should detect any unauthorized modifications to stored documents and notify the user when attempting to download such documents.

The application assumes the existence of a public key infrastructure. All certificates should be issued by a Certificate Authority (CA) established before the application's operation. Assume that the CA certificate, Certificate Revocation List (CRL), user certificates, and the private key of the currently logged-in user are located at an arbitrary location on the file system (no need to implement key exchange mechanisms). User certificates should be limited to usage only for the purposes required by the application. Additionally, the data within the certificate should be associated with corresponding user information.

User certificates are issued for a period of 6 months. Furthermore, if a user enters incorrect credentials three times during a single login session, their certificate is automatically suspended, and the application displays an appropriate message. Afterward, the application offers the user the option to reactivate the certificate (by entering correct credentials) or register a new account.

For any task details not explicitly specified, implement them in an arbitrary manner. The use of any programming language and suitable library for cryptographic functions (e.g., Bouncy Castle) is allowed. The implementation details of the user interface will not be evaluated.

This project task is applicable from the first session of the January-February 2023 examination period and remains valid until the release of the next project task.
