# Test Express

Test app to demo Reflected XSS vulnerability

## How To Run

1 Make sure you are into directory TestExpress
2 Rub below command on terminal
```
node app
```
3 App is running port 3000
See xss demo on 

```
http://localhost:3000/xss?tagline=""><script>alert(document.domain)</script>
```