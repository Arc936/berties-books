# Berties Books

Sample code for Dynamic Web Applications module.

Uses node.js with Express and EJS.

To install and run:

npm install
node index.js

Ensures the input string is a correctly formatted email address. This is crucial for communication and prevents errors during data processing.
Enforces minimum (5) and maximum (20) character limits. This prevents excessively long strings which could degrade performance and provides a basic layer of bot mitigation.
Remove white spoaces where it could mess up the sanitisation.

Validation ensures the data conforms to a strict format, which is often more effective than generic sanitization for these specific data types.
The password is not sanitized because it is immediately hashed using bcrypt before being stored. The original plain text is never stored or used in any context where sanitization would be relevant.