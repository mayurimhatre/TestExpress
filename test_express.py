import pytest
import time
import sys
import os
import requests
import socket
from threading import Thread

sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..','')))
from BaseTestApp import BaseTestApp

class Test_Express(BaseTestApp):
    
    host = "localhost"
    port = 3000
    app_name = "app.js"
    test_folder = os.path.dirname(__file__)
    path = test_folder
    startup_success_log = "Server for TestExpress app listening on port 3000!"

    def test_CWE_95(self):
        self.server.http_get('/evalDemo?preTax=0') 
        assert self.server.expect_annotation(50), "Failed TP CWE-95"
        return True

    def test_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed TP send CWE-79"
        return True

    
    def test_render_tp_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssRender?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed TP render CWE-79"
        return True

    def test_send_fp_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_he_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP render CWE-79"
        return True

    def test_send_tp_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_he_encode2?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed TP send CWE-79"
        return True

    @pytest.mark.skip
    def test_send_fn_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_he_encode3?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed FN send CWE-79"
        return True

    def test_send_fp_escape_html_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_escape_html_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP escape_html CWE-79"
        return True

    def test_send_fp_xss_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_xss_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP xss CWE-79"
        return True

    def test_send_fp_stringify_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_stringify_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP stringify CWE-79"
        return True

    def test_send_fp_ent_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_ent_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP ent CWE-79"
        return True

    @pytest.mark.skip
    def test_send_fn_ent_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_ent_encode2?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed FN ent CWE-79"
        return True

    def test_send_fp_entities_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_entities_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP entities CWE-79"
        return True

    @pytest.mark.skip
    def test_send_fn_entities_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_entities_encode2?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed FN entities CWE-79"
        return True

    def test_send_fp_html_entities_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_htmlEntities_encode1?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_no_annotation(50), "Failed FP html-entities CWE-79"
        return True

    @pytest.mark.skip
    def test_send_fn_html_entities_CWE_79(self):
        # ?tagline=""><script>alert(document.domain)</script>
        self.server.http_get('/xssSend_htmlEntities_encode2?tagline=""><script>alert(document.domain)</script>')
        assert self.server.expect_annotation(50), "Failed FN html-entities CWE-79"
        return True

    def test_CWE_601(self):
        # ?tagline=maliciouwebsite
        self.server.http_get('/redirectDemo?tagline=maliciouwebsite')
        assert self.server.expect_annotation(50), "Failed TP CWE-601"
        return True

    def test_CWE_113(self):
        # ?tagline=malicious
        self.server.http_get('/responseSpitDemo?key=myKey&value=myValue')
        assert self.server.expect_annotation(50), "Failed TP CWE-113"
        return True

    @pytest.mark.skip
    def test_CWE_201(self):
        # ?tagline=malicious
        self.server.http_get('/dataExfiltrationDemo?tagline=malicious')
        assert self.server.expect_annotation(50), "Failed TP CWE-201"
        return True

    def test_CWE_73(self):
        # ?tagline=package.json
        self.server.http_get('/filePathCtrlDemo?tagline=package.json')
        assert self.server.expect_annotation(50), "Failed TP CWE-73"
        return True