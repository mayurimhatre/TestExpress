var express = require('express');
var he = require('he');
var xss = require("xss");
var stringify = require('stringify-entities');
var ent = require('ent');
var entities = require('entities');
var HtmlEntities = require('html-entities').AllHtmlEntities;
const htmlEntities = new HtmlEntities();
var escapeHtml = require('escape-html')

var app = express();

app.set('view engine', 'ejs');

var server = app.listen(3000, function () {
  console.log('Server for TestExpress app listening on port 3000!');
});

module.exports = server;


app.get('/', function (req, res) {
  res.send('Welcome to Test Express!');
});

// CWE-95
// http://localhost:3000/evalDemo?preTax=0
app.get("/evalDemo", function(req, res) {
  var preTax = eval(req.query.preTax);
  res.send("This is eval demo for TestExpress application!");
});

// CWE-79
// http://localhost:3000/xssSend?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend', function (req, res) {
  res.send("<p>this: "+req.query.tagline+"</p>")
});

// CWE-79 
// http://localhost:3000/xssRender?tagline=""><script>alert(document.domain)</script>
app.get('/xssRender', function (req, res) {
  res.render('xssGetDemo.ejs', {tagline: req.query.tagline});
});

// CWE-79 FP
// http://localhost:3000/xssSend_he_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_he_encode1', function (req, res) {
  encoded_tagline = he.encode(req.query.tagline)
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 TP
// http://localhost:3000/xssSend_he_encode2?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_he_encode2', function (req, res) {
  encoded_tagline = he.encode(req.query.tagline) + req.query.tagline
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 FN //TODO
// http://localhost:3000/xssSend_he_encode3?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_he_encode3', function (req, res) {
  encoded_tagline = he.encode(req.query.tagline)
  res.send("<p>this: "+he.decode(encoded_tagline)+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_escape_html_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_escape_html_encode1', function (req, res) {
  encoded_tagline = escapeHtml(req.query.tagline)
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_xss_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_xss_encode1', function (req, res) {
  encoded_tagline = xss(req.query.tagline)
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_stringify_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_stringify_encode1', function (req, res) {
  //encoded_tagline = stringify(req.query.tagline, {subset : ['&']})
  encoded_tagline = stringify(req.query.tagline)
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_ent_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_ent_encode1', function (req, res) {
  encoded_tagline = ent.encode(req.query.tagline)
  res.send("<p>this: "+encoded_tagline+"</p>")
});

// CWE-79 FN // TODO
// http://localhost:3000/xssSend_ent_encode2?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_ent_encode2', function (req, res) {
  encoded_tagline = ent.encode(req.query.tagline)
  res.send("<p>this: "+ ent.decode(encoded_tagline)+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_entities_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_entities_encode1', function (req, res) {
  encoded_tagline = entities.encode(req.query.tagline)
  res.send("<p>this: "+ encoded_tagline+"</p>")
  
});

// CWE-79 FN // TODO
// http://localhost:3000/xssSend_entities_encode2?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_entities_encode2', function (req, res) {
  encoded_tagline = entities.encode(req.query.tagline)
  res.send("<p>this: "+ entities.decode(encoded_tagline)+"</p>")
});

// CWE-79 FP
// http://localhost:3000/xssSend_htmlEntities_encode1?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_htmlEntities_encode1', function (req, res) {
  encoded_tagline = htmlEntities.encode(req.query.tagline)
  res.send("<p>this: "+ encoded_tagline+"</p>")
  
});

// CWE-79 FN // TODO
// http://localhost:3000/xssSend_htmlEntities_encode2?tagline=""><script>alert(document.domain)</script>
app.get('/xssSend_htmlEntities_encode2', function (req, res) {
  encoded_tagline = htmlEntities.encode(req.query.tagline)
  res.send("<p>this: "+ htmlEntities.decode(encoded_tagline)+"</p>")
  
});

// CWE-601
// http://localhost:3000/redirectDemo?tagline=maliciouwebsite
app.get('/redirectDemo', function (req, res) {
  res.redirect("http://localhost:3000/xssSend?tagline="+req.query.tagline);
});

// CWE-113
// http://localhost:3000/responseSpitDemo?key=myKey&value=myValue
app.get('/responseSpitDemo', function (req, res) {
  res.append(req.query.key, req.query.value);
  res.status(200).send('Check your headers!');
});

// CWE-201
// http://localhost:3000/dataExfiltrationDemo?tagline=malicious
app.get('/dataExfiltrationDemo', function (req, res) {
  res.json(req.query.tagline);
});

// CWE-73
// http://localhost:3000/filePathCtrlDemo?tagline=malicious
app.get('/filePathCtrlDemo', function (req, res) {
  res.download(req.query.tagline, function(err){
    if (err) {
      console.log('Error downloading file');
    } else {
      console.log('File downloaded');
    }
  });
});


var gracefulShutdown = function() {
  console.log("Received shutdown command, shutting down gracefully.");
  process.exit();
}

// listen for TERM signal (e.g. kill command issued by forever).
process.on('SIGTERM', gracefulShutdown);

// listen for INT signal (e.g. Ctrl+C).
process.on('SIGINT', gracefulShutdown);

module.exports = app;