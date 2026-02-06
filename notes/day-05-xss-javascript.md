## Day 05 – Cross Site Scripting (XSS)

Cross Site Scripting (XSS) is a web security vulnerability where attackers inject malicious JavaScript into a web page.

XSS happens when user input is not properly handled and is rendered as executable code in the browser.

---

### Types of XSS
- Stored XSS
- Reflected XSS
- DOM-based XSS

This demo focuses on DOM-based XSS.

---

### Vulnerable Code Example
Using `innerHTML` directly with user input causes XSS.

```javascript
output.innerHTML = userInput;