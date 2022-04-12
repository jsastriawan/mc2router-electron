var fs = require("fs");
var request = require('request');
var constants = require('constants');
var tls_options = { rejectUnauthorized: false, strictSSL: false, secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1 };
var specialRequest = request.defaults(tls_options);
var net = require('net');
var spawn = require('child_process');
var WebSocket = require('ws');
var Url = require('url');
var querystring = require("querystring");
var https = require('https');
var nodes = {};
var fnodes = {};
var cmds = {};
var meshes = {};

function Q(x) { return document.getElementById(x); }                            // "Q"
function QS(x) { try { return Q(x).style; } catch (x) { } }                     // "Q" style
function QE(x, y) { try { Q(x).disabled = !y; } catch (x) { } }                 // "Q" enable
function QV(x, y) { try { QS(x).display = (y ? '' : 'none'); } catch (x) { } }  // "Q" visible
function QA(x, y) { Q(x).innerHTML += y; }                                      // "Q" append
function QH(x, y) { Q(x).innerHTML = y; }                                       // "Q" html

function onload_handler() {
    setPanel(1);
    loadConfig();
    loadCmds();
}

function performLogin() {
    setPanel(2);
    // just resolve proxy IP address on th fly, socks-proxy-agent doesn't understand FQDN proxy address
    if (document.getElementsByName("use_proxy")[0].checked == true) {
        resolveProxyIP(function () {
            loadMeshes();
        })
    } else {
        loadMeshes();
    }
}

function setPanel(number) {
    for (var i = 0; i < 10; i++) { try { QV('panel' + i, i == number); } catch (e) { } }
}


function loadCmds() {
    try {
        var platform = process.platform;        
        var temp_obj = {}
        if (fs.existsSync("cmds-"+platform+".json")) {
            temp_obj = JSON.parse(fs.readFileSync("cmds-"+platform+".json"));
        } else {
            temp_obj = JSON.parse(fs.readFileSync("cmds.json"));
        }
        if (temp_obj != null && temp_obj.cmds != null && temp_obj.cmds.length != null) {
            cmds = {};
            for (var j = 0; j < temp_obj.cmds.length; j++) {
                var c = temp_obj.cmds[j];
                cmds[c.id] = c;
            }
        }
    } catch (e) {
        console.log("Unable to load command list");
    }
    if (Object.keys(cmds).length > 0) {
        QH("select_cmd_div", ""); //clear out list container
        for (var idx in Object.keys(cmds)) {
            var cmd = Object.values(cmds)[idx];
            var str = "<span class='nav-group-item small' id='dcmd_" + cmd.id + "'>";
            str += "<input type='radio' name='select_cmd_radio' value='cmd_" + cmd.id + "' style='vertical-align: middle; margin-top: -1px;'>&nbsp;";
            str += cmd.label + "<br/>";
            str += "</span>";
            QA("select_cmd_div", str);
        }
    }
}

function readForm() {
    var data = {};
    data["mesh_url"] = document.getElementsByName("mesh_url")[0].value;
    data["mesh_username"] = document.getElementsByName("mesh_username")[0].value;
    data["mesh_password"] = document.getElementsByName("mesh_password")[0].value;
    data["save_password"] = document.getElementsByName("save_password")[0].checked
    data["ssh"] = document.getElementsByName("ssh")[0].value;
    data["sftp"] = document.getElementsByName("sftp")[0].value;
    data['rdp'] = document.getElementsByName("rdp")[0].value;
    data["use_proxy"] = document.getElementsByName("use_proxy")[0].checked;
    data["proxy_type"] = document.querySelector('input[name="proxy_type"]:checked').value;
    data["proxy_host"] = document.getElementsByName("proxy_host")[0].value;
    data["proxy_port"] = document.getElementsByName("proxy_port")[0].value;
    var idx = document.getElementById("select_mesh").selectedIndex;
    if (idx >= 0) {
        data["meshidhex"] = document.getElementById("select_mesh").options[idx].value;
    } else {
        data["meshidhex"] = null;
    }
    if (document.querySelector('input[name="select_node_radio"]:checked') != null) {
        data["nodeidhex"] = document.querySelector('input[name="select_node_radio"]:checked').value;
    } else {
        data["nodeidhex"] = null;
    }
    return data;
}

function loadConfig() {
    try {
        var cfg = JSON.parse(fs.readFileSync("config.json"));
        if (typeof cfg.mesh_password != undefined) {
            cfg.mesh_password = "";
        }
        // use base 64 string instead if defined
        if (typeof cfg.mesh_passwordb64 != undefined) {
            try {
                var dstr = Buffer.from(cfg.mesh_passwordb64, 'base64').toString();
                cfg.mesh_password = dstr;
            } catch (e) {
                cfg.mesh_password = "";
            }
        }

        document.getElementsByName("mesh_url")[0].setAttribute('value', cfg.mesh_url);
        document.getElementsByName("mesh_username")[0].setAttribute('value', cfg.mesh_username);
        document.getElementsByName("mesh_password")[0].setAttribute('value', cfg.mesh_password);
        document.getElementsByName("save_password")[0].checked = cfg.save_password;
        document.getElementsByName("use_proxy")[0].checked = cfg.use_proxy;
        var rb = document.getElementsByName("proxy_type");
        for (var i = 0; i < rb.length; i++) { if (rb[i].value == cfg.proxy_type) { rb[i].checked = true; } }
        document.getElementsByName("proxy_host")[0].setAttribute('value', cfg.proxy_host);
        document.getElementsByName("proxy_port")[0].setAttribute('value', cfg.proxy_port);
        document.getElementsByName("ssh")[0].setAttribute('value', cfg.ssh);
        document.getElementsByName("sftp")[0].setAttribute('value', cfg.sftp);
        document.getElementsByName("rdp")[0].setAttribute('value', cfg.rdp);
        useProxyChanged();
    } catch { }
}

function saveConfig() {
    var cfg = readForm();
    delete cfg["meshidhex"];
    delete cfg["nodeidhex"];
    if (cfg["save_password"] == true) {
        // encode password with base64
        try {
            var bstr = Buffer.from(cfg["mesh_password"]).toString('base64');
            cfg["mesh_passwordb64"] = bstr;
            delete cfg["mesh_password"];// do not save clear text password
        } catch (e) { }
    } else {
        delete cfg["mesh_password"];// do not save clear text password
        delete cfg["mesh_passwordb64"];// do not save base64 password
    }
    fs.writeFileSync('config.json', JSON.stringify(cfg, null, '\t'));
}

function resolveProxyIP(cb) {
    var proxy_host = document.getElementsByName("proxy_host")[0].value;
    var dns = require('dns');
    dns.lookup(proxy_host, function (err, addr, fam) {
        if (!err) {
            //console.log('Resolved proxy IP: '+ addr);
            document.getElementsByName("proxy_host")[0].value=addr;
        } else {
            //console.log('Resolve proxy error: ' + err);
        }
        if (cb) { cb() };
    })
}

function useProxyChanged() {
    var up_ticked = document.getElementsByName("use_proxy")[0].checked;
    if (up_ticked) {
        document.getElementsByName("proxy_host")[0].disabled = false;
        document.getElementsByName("proxy_port")[0].disabled = false;
    } else {
        document.getElementsByName("proxy_host")[0].disabled = true;
        document.getElementsByName("proxy_port")[0].disabled = true;
    }
}

function updateSshInput() {
    var fn = document.getElementsByName('ssh_file')[0].files[0].path;
    document.getElementsByName('ssh')[0].setAttribute('value', fn);
}

function updateSftpInput() {
    var fn = document.getElementsByName('sftp_file')[0].files[0].path;
    document.getElementsByName('sftp')[0].setAttribute('value', fn);
}

function updateRdpInput() {
    var fn = document.getElementsByName('rdp_file')[0].files[0].path;
    document.getElementsByName('rdp')[0].setAttribute('value', fn);
}

function loadMeshes() {
    nodes = {};
    var data = readForm();
    var proxyagent = null;
    if (data["use_proxy"] && data["proxy_type"] == "http") {
        var HttpProxyAgent = require('https-proxy-agent');
        proxyagent = new HttpProxyAgent("http://" + data["proxy_host"] + ":" + data["proxy_port"]);
    } else if (data["use_proxy"] && data["proxy_type"] == "socks") {
        //socks proxy only accept IP, if it is not IP, it must be resolved first
        var ip = require('ip');
        if (!ip.isV4Format(data['proxy_host']) && !ip.isV6Format(data['proxy_host'])) {
            alert("Please resolve socks proxy host at the configuration and save");
            setPanel(1);
            return;
        }
        // sock agent init
        var SocksProxyAgent = require('socks-proxy-agent');
        proxyagent = new SocksProxyAgent('socks5://' + data['proxy_host'] + ':' + data['proxy_port'], true);
    }


    var cred = { username: data["mesh_username"], password: data["mesh_password"] };
    var url = new Url.URL(data["mesh_url"]);
    // prepare request options
    var auth_postdata = querystring.stringify(cred);
    var options = JSON.parse(JSON.stringify(tls_options));
    options.hostname = url.hostname;
    options.method = "POST";
    options.port = (url.port == "" || url.port == null) ? "443" : url.port;
    options.path = "/login";
    options.timeout = 10000;
    options.followRedirect = true;
    options.maxRedirects = 10;
    options.headers = {
        'Content-type': 'application/x-www-form-urlencoded',
        'Content-length': Buffer.byteLength(auth_postdata)
    }

    if (proxyagent != null) {
        options.agent = proxyagent;
    }

    //console.log(JSON.stringify(options));
    // authenticate
    var req = https.request(options, function (res) {        
        if (res.statusCode == 200 || res.statusCode == 302) {            
            if (res.headers['set-cookie'] === undefined) {
                window.alert("Login failed.");
                setPanel(1);
                return;
            }
            var ws_headers = {
                'Cookie': res.headers['set-cookie']
            };

            var ws_options = JSON.parse(JSON.stringify(tls_options));
            ws_options.headers = ws_headers;
            ws_options.agent = proxyagent;
            var WebSocket = require('ws');
            var ws = new WebSocket('wss://' + options.hostname + ":" + options.port + "/control.ashx", [], ws_options);
            ws.on('open', function () {
                //console.log("WS open");
                var jstr = { "action": "nodes" };
                ws.send(JSON.stringify(jstr));
            });

            ws.on('close', function (code, reason) {
                //console.log('WS close:' + code + ":" + reason);
            });

            ws.on('error', function (er) {
                //console.log('WS error:' + er);
            });

            ws.on('message', function (data) {
                var msg = null;
                try {
                    msg = JSON.parse(data);
                } catch (e) {
                    msg = data;
                }
                //console.log('WS message: ' + new Date().toString() + '\n' + JSON.stringify(msg,null,"   "));
                if (msg.action == "nodes") {
                    nodes = JSON.parse(JSON.stringify(msg.nodes));
                    // build meshes list with unknown name = set as individual devices
                    meshes = [];
                    Object.keys(nodes).forEach(m =>{       
                        meshes[m] = { _id: m, name: "Individual Devices"};
                    });
                    // build nodes flat list                            
                    fnodes = [];                            
                    Object.values(nodes).forEach(m =>{                                
                        m.forEach(el => {
                            fnodes[el._id]=el;
                        });
                    });
                    //console.log(JSON.stringify(fnodes,null,3));
                    //console.log(JSON.stringify(nodes));
                    var jstr = { "action": "meshes" };
                    ws.send(JSON.stringify(jstr));
                } else if (msg.action == "meshes") {
                    if (msg.meshes) {
                        var tmeshes = JSON.parse(JSON.stringify(msg.meshes));
                        Object.values(tmeshes).forEach(m=>{                                    
                            if (meshes[m._id]!=null) {
                                meshes[m._id].name = m.name;
                            }
                        });
                        var select_mesh = document.getElementById("select_mesh");
                        select_mesh.options.length = 0;
                        for (var i in meshes) {
                            var opt = document.createElement("option");
                            opt.text = meshes[i].name;
                            opt.setAttribute("value", meshes[i]._id);
                            select_mesh.add(opt);
                        }                                

                        if (tmeshes.length>0) {                                    
                            select_mesh.options[0].selected = true;
                            meshChanged(select_mesh);
                        }
                    }
                    setPanel(4);
                    ws.close();// just close it
                }
            });

        }
        res.on("data", function (chunk) {
            //console.log(chunk.toString());
        });
    });
    req.write(auth_postdata);
    req.end();
}

function loadNodes(meshidhex) {
    QH("select_node_div","");// clear out list container
    if (Object.keys(nodes).indexOf(meshidhex) >= 0) {
        var node_list = Object.values(nodes)[Object.keys(nodes).indexOf(meshidhex)];
        for (var i = 0; i < node_list.length; i++) {
            var str = "<span class='nav-group-item small' id='"+(node_list[i]._id).replace(/\/+/,'')+"'>";
            str += "<input type='radio' name='select_node_radio' value='"+node_list[i]._id+"' style='vertical-align: middle; margin-top: -1px;'>&nbsp;";
            if (!node_list[i].icon || node_list[i].icon>6 ) {
                node_list[i].icon=1;
            }
            if (node_list[i].conn != null && node_list[i].conn != 0) {
                str += "<img class='mini_icon_on' src='icons200-" + node_list[i].icon + "-1.png'>&nbsp;";
            } else {
                str += "<img class='mini_icon_off' src='icons200-" + node_list[i].icon + "-1.png'>&nbsp;";
            }
            str += node_list[i].name+"<br/>";
            str +="</span>";
            QA("select_node_div",str);
        }                
    }
}

function meshChanged(obj) {
    loadNodes(obj.value);
    nsearchInputChanged();
}

function nsearchInputChanged() {            
    var x = Q('nsearch').value.toLowerCase().trim();            
    var meshidhex = Q('select_mesh').value;
    var node_list = Object.values(nodes)[Object.keys(nodes).indexOf(meshidhex)];
    if (x == '') {
        for (var d in node_list) {
            QV(node_list[d]._id.replace(/\/+/, ''), true);
        }
    } else {                
        var rs = x.split(/\s+/).join('|');
        var rx = new RegExp(rs);
        for (var d in node_list) {
            var nid= node_list[d]._id.replace(/\/+/, '');
            var nd = Q(nid);
            var vsb = (rx.test(node_list[d].name.toLowerCase())) || (node_list[d].hostl != null && rx.test(node_list[d].hostl.toLowerCase()));
            QV(nid,vsb);
            if ((vsb == false) && node_list[d].tags) {
                for (var s in node_list[d].tags) {
                    if (rx.test(node_list[d].tags[s].toLowerCase())) {
                        QV(nid,true);                                
                        break;
                    } else {
                        QV(nid,false);                                
                    }
                }
            }
        }
    }
}


function performLogin() {
    setPanel(3);
    // just resolve proxy IP address on th fly, socks-proxy-agent doesn't understand FQDN proxy address
    if (document.getElementsByName("use_proxy")[0].checked == true) {
        resolveProxyIP(function () {
            loadMeshes();
        })
    } else {
        loadMeshes();
    } 
}

function toggleRemoteIP() {
    QV("remote_ip",Q("cb_relay").checked);
}

function createPipeAndExec(exepath, args, opts, tunnelcfg) {
    if (Q("cb_relay").checked) {
        var thost = document.getElementById("remote_ip").value;
        if (thost == "" || net.isIP(thost)==0) {
            window.alert("Invalid IP, action cancelled");
            return;
        } else {
            if (net.isIP(thost)>0) {
                var ntunnelcfg = tunnelcfg;
                ntunnelcfg["tcpaddr"]=thost;
                createPipeAndExecEx(exepath, args, opts, ntunnelcfg)
            } else {
                window.alert("Invalid IP, assume 127.0.0.1");
                createPipeAndExecEx(exepath, args, opts, tunnelcfg)
            }
        }
    } else {
        createPipeAndExecEx(exepath, args, opts, tunnelcfg)
    }
}

function createPipeAndExecEx(exepath, args, opts, tunnelcfg) {
    // sanity check
    if (!fs.existsSync(exepath)) {
        alert("File "+exepath+" is not found.");
        return;
    }

    if (tunnelcfg==null || tunnelcfg.nodeid==null) {
        alert("Invalid tunnel request configuration.");
        return;
    }
    // proxy setting
    var frm_data = readForm();
    var use_proxy = frm_data["use_proxy"];
    var proxy_type = frm_data["proxy_type"];
    var proxy_host = frm_data["proxy_host"];
    var proxy_port = frm_data["proxy_port"];

    var proxyagent = null;
    if (frm_data["use_proxy"] && frm_data["proxy_type"] == "http") {
        var HttpProxyAgent = require('https-proxy-agent');
        proxyagent = new HttpProxyAgent("http://" + frm_data["proxy_host"] + ":" + frm_data["proxy_port"]);
    } else if (frm_data["use_proxy"] && frm_data["proxy_type"] == "socks") {
        // sock agent init
        var SocksProxyAgent = require('socks-proxy-agent');
        proxyagent = new SocksProxyAgent('socks://' + frm_data['proxy_host'] + ':' + frm_data['proxy_port'], true);
    }

    var cred = { username: frm_data["mesh_username"], password: frm_data["mesh_password"] };
    var url = Url.parse(frm_data["mesh_url"]);

    // tcp server
    var tcpserver = net.createServer();

    // handling client connection
    tcpserver.on("connection", function (csock) {
        // create buffer data
        csock.xdata = null;
        // prepare request options
        var ws_options = JSON.parse(JSON.stringify(tls_options));
        if (proxyagent != null) {
            ws_options.agent = proxyagent;
        }

        var port = (url.port == null) ? "443" : url.port

        var wsurl = "wss://" + url.hostname + ":" + port + "/meshrelay.ashx?";
        wsurl += "user=" + cred.username;
        wsurl += "&pass=" + cred.password;

        if (tunnelcfg["id"]) {
            wsurl += "&id=" + tunnelcfg["id"];
        }
        if (tunnelcfg["nodeid"]) {
            wsurl += "&nodeid=" + tunnelcfg["nodeid"];
        }
        if (tunnelcfg["port"]) {
            wsurl += "&tcpport=" + tunnelcfg["port"];
        }
        if (tunnelcfg["tcpaddr"]) {
            wsurl += "&tcpaddr=" + tunnelcfg["tcpaddr"];
        }
        if (tunnelcfg['protocol']) {
            wsurl += "&p=" +tunnelcfg['protocol'];
        }
        if (tunnelcfg['browser']) {
            wsurl += "&browser=" +tunnelcfg['browser'];
        }
        
        if (tunnelcfg["auth"]) {
            wsurl+="&auth="+ tunnelcfg["auth"];
        }

        if (tunnelcfg["rauth"]) {
            wsurl+="&rauth="+ tunnelcfg["rauth"];
        }

        //console.log("WSURL: "+wsurl);

        var ws = new WebSocket(wsurl, [], ws_options);
        // wiring up
        ws.csock = csock;
        ws.connected = false;
        csock.ws = ws;

        if (tunnelcfg["protocol"]) {
            // handle terminal
            ws.tprotocol = tunnelcfg["protocol"];
            if (tunnelcfg["protocol"]==1) {
                var currentnode = fnodes[tunnelcfg["nodeid"]];
                csock.agenttype = ([1, 2, 3, 4, 21, 22].indexOf(currentnode.agent.id) >= 0) ? "windows" : "linux";                        
            }
        }

        ws.on('open', function () {
            //console.log("WS open");                    
        });

        ws.on('close', function (code, reason) {
            //console.log('WS close:' + code + ":" + reason);
            csock.ws = null;
            try {
                csock.end();
            } catch (e) {
                //console.log(e);
            }
        });

        ws.on('error', function (er) {
            console.log('WS error:' + er);
        });

        ws.on('message', function (msg) {
            //console.log('WS message: ' + msg);
            if (ws.connected && ws.csock != null) {
                //console.log("Data from WS: " + Buffer.byteLength(msg));
                try {
                    //ws.pause();
                    //console.log("Sending to CSOCK: "+ msg);
                    ws.csock.write(msg, function() {
                        //try {ws.resume();} catch (ex) {console.log(ex)}
                    });
                } catch (e) {
                    console.log(e);
                }
            } else if (msg.toString() == 'c') {
                //console.log("Receive c");
                // send tunneling protocol if set.
                if (ws.tprotocol) {                            
                    //console.log("Send "+ws.tprotocol);
                    ws.send(ws.tprotocol);                            
                }
                ws.connected = true;
                // send pending data
                if (ws.csock.xdata != null) {
                    // Telnet terminal negotiation detection and response to force local echo and line mode off
                    if (ws.tprotocol && ws.tprotocol==1 && (ws.csock.xdata.length % 3 == 0)) {
                        var cnt = ws.csock.xdata.length/3;
                        // see: 
                        // - http://www.tcpipguide.com/free/t_TelnetProtocolCommands-3.htm
                        // - http://www.iana.org/assignments/telnet-options/telnet-options.xhtml
                        // will echo, do suppress ahead, will suppress ahead
                        var tbuf = Buffer.from([0xff,0xfb,0x01,0xff,0xfd,0x03,0xff,0xfb,0x03]);                                
                        // console.log("Sending buffer to csock: " + tbuf.toString('hex'));
                        try {
                            csock.write(tbuf);
                        } catch (e) {
                            console.log(e);
                        }
                    }
                    //console.log("Sending buffer to WS: " + ws.csock.xdata.toString('hex'));                            
                    try {
                        ws.send(Buffer.from(ws.csock.xdata,"binary"));
                        ws.csock.xdata = null;
                    } catch (e) {
                        console.log(e);
                    }
                }
            }
        });
        // csock eventing
        csock.on("data", function (chunk) {
            if (csock.ws != null && csock.ws.connected == true) {
                try {
                    //csock.pause();
                    if (csock.xdata != null) {
                        //console.log("Sending buffer to WS: " + chunk);
                        if (csock.ws.tprotocol && csock.ws.tprotocol==1 && csock.agenttype && csock.agenttype=="linux") {
                            csock.ws.send(csock.xdata.replace(/\r\n/g,'\r'));
                        } else {
                            csock.ws.send(csock.xdata);
                        }
                        csock.xdata = null;
                    }
                    var nchunk = chunk;
                    if (csock.ws.tprotocol && csock.ws.tprotocol==1 && csock.agenttype && csock.agenttype=="linux") {
                        nchunk = chunk.toString().replace(/\r\n/g,'\r');
                    }
                    //console.log("Data from client: " + nchunk.toString('hex'));                            
                    csock.ws.send(Buffer.from(nchunk,'binary'), function(err) {
                        if (err!=null) {
                            console.log(err);
                        }
                        //try { csock.resume()} catch (e) {console.log(e)}
                    });
                } catch (e) {
                    console.log(e);
                }
            } else {
                //console.log("Put data into buffer: "+chunk);
                if (csock.xdata == null) {
                    csock.xdata = chunk;
                } else {
                    csock.xdata += chunk;
                }
            }
        });

        csock.on("error", function (e) {
            //console.log(e);
            csock.ws.csock = null;
        });

        csock.on("end", function () {
            //console.log("Client Socket end");
            if (csock.ws != null) {
                csock.ws.close();
            }
        })

        csock.on("close", function () {
            //console.log("Client Socket close");
            if (csock.ws != null) {
                csock.ws.close();
            }
        })

    });

    tcpserver.listen(0, '127.0.0.1', function () {
        var lport = tcpserver.address()["port"];
        //console.log("Local port is: "+lport);
        var idx = args.indexOf('lport');
        if (idx >= 0) {
            args[idx] = lport;
        } else {
            for (var i = 0; i < args.length; i++) {
                if (args[i].endsWith("lport")) {
                    var newstr = args[i].replace("lport", "" + lport);
                    args[i] = newstr;
                    //console.log("Replace lport: "+newstr);
                }
            }
        }
        //console.log("Exepath:"+exepath+" "+JSON.stringify(args));
        var cp = spawn.spawn(exepath, args, opts);
        cp.on("exit", function () {
            try {
                //console.log("Shutting down TCPServer");
                tcpserver.close();
            } catch (e) {
                //console.log("Error: " + e);
            }
        });
    });
}

function sendControlCommand(cmd, waitfor, cb) {
    var data = readForm();
    var proxyagent = null;
    if (data["use_proxy"] && data["proxy_type"] == "http") {
        var HttpProxyAgent = require('https-proxy-agent');
        proxyagent = new HttpProxyAgent("http://" + data["proxy_host"] + ":" + data["proxy_port"]);
    } else if (data["use_proxy"] && data["proxy_type"] == "socks") {
        //Not validating IP anymore assuming login already handle it
        // sock agent init
        var SocksProxyAgent = require('socks-proxy-agent');
        proxyagent = new SocksProxyAgent('socks5://' + data['proxy_host'] + ':' + data['proxy_port'], true);
    }

    var cred = { username: data["mesh_username"], password: data["mesh_password"] };
    var url = Url.parse(data["mesh_url"]);
    // prepare request options
    var auth_postdata = querystring.stringify(cred);
    var options = JSON.parse(JSON.stringify(tls_options));
    options.hostname = url.hostname;
    options.method = "POST";
    options.port = (url.port == null) ? "443" : url.port;
    options.path = "/login";
    options.timeout = 10000;
    options.followRedirect = true;
    options.maxRedirects = 10;
    options.headers = {
        'Content-type': 'application/x-www-form-urlencoded',
        'Content-length': Buffer.byteLength(auth_postdata)
    }

    if (proxyagent != null) {
        options.agent = proxyagent;
    }

    //console.log(JSON.stringify(options));
    // authenticate
    var req = https.request(options, function (res) {
        if (res.statusCode == 200 || res.statusCode == 302) {
            var ws_headers = {
                'Cookie': res.headers['set-cookie']
            };

            var ws_options = JSON.parse(JSON.stringify(tls_options));
            ws_options.headers = ws_headers;
            ws_options.agent = proxyagent;
            var WebSocket = require('ws');
            var ws = new WebSocket('wss://' + options.hostname + ":" + options.port + "/control.ashx", [], ws_options);
            var waittimeout = false;
            var waittimer;                    
            ws.on('open', function () {
                //console.log("CMD WS open");
                ws.send(JSON.stringify(cmd));
                //console.log("CMD WS send: "+JSON.stringify(cmd));
                // wait for 3 seconds if waitfor is set
                if (waitfor!=null) { 
                    waittimer=setTimeout(function(){
                        waittimeout=true;
                    },3000);
                } else {
                    ws.close();                                                        
                }                        
            });

            ws.on('close', function (code, reason) {
                //console.log('CMD WS close:' + code + ":" + reason);                        
            });

            ws.on('error', function (er) {
                //console.log('CMD WS error:' + er);
            });

            ws.on('message', function (data) {                        
                var msg = null;
                try {
                    msg = JSON.parse(data);
                } catch (e) {
                    msg = data;
                }
                if (waitfor==null) {
                    ws.close();// just close it
                    if (cb)  {
                        cb(msg); //return the last message
                        cb=null;
                    }
                } else {
                    if (msg.action==waitfor) {
                        clearTimeout(waittimer);
                        ws.close();// just close it
                        if (cb)  {
                            cb(msg); //return the resulting message
                            cb=null;
                        }   
                    } else if (waittimeout==true) {
                        if (cb)  {
                            cb(null); //return the resulting message
                            cb=null;
                        }
                    }
                }
            });

        }
        res.on("data", function (chunk) {
            //console.log(chunk.toString());
        });
    });
    req.write(auth_postdata);
    req.end();            
}

function termClicked() {
    var data = readForm();
    var exepath = data['ssh'];
    var args = ['-telnet','127.0.0.1','-P','lport'];
    var tunnelcfg = {
        nodeid: data["nodeidhex"],
        id: Math.random().toString(36).substring(2), // random tunnel id
        protocol: 1 // terminal
    };
    // send message via control.ashx to create tunnel with certain id
    var cmd = {
        action: "msg",
        type: "tunnel",
        nodeid: data["nodeidhex"],
        usage: tunnelcfg["protocol"],
        value: "*/meshrelay.ashx?p=1&nodeid="+tunnelcfg["nodeid"]+"&id="+tunnelcfg['id']
    }

    var authcookiecmd = {
        action: "authcookie"
    }

    sendControlCommand(authcookiecmd, "authcookie", function (c) {
        if (c!=null) {
            //console.log("Authcookie:"+JSON.stringify(c));
            cmd.value = cmd.value+"&rauth="+c.rcookie;
            tunnelcfg["auth"]= c.cookie;
            tunnelcfg["rauth"]=c.rcookie;
        }
        sendControlCommand(cmd, null, function (x) {
            createPipeAndExec(exepath, args, {}, tunnelcfg);
        });
    });
}

function sshClicked() {
    var data = readForm();
    var exepath = data['ssh'];
    var args = ['-ssh', '127.0.0.1', '-P', 'lport'];
    var tunnelcfg = {
        nodeid: data["nodeidhex"],
        port: 22
    };
    createPipeAndExec(exepath, args, {}, tunnelcfg);
}

function sftpClicked() {
    var data = readForm();
    var exepath = data['sftp'];
    var user = document.getElementById("remote_username").value;
    if (user == null) {
        window.alert("SFTP cannot be invoked without passing username!");
        return;
    }
    var tunnelcfg = {
        nodeid: data["nodeidhex"],
        port: 22
    };
    var args = ['--verbose', 'sftp://' + user + '@127.0.0.1:lport', '-l=ask'];
    createPipeAndExec(exepath, args, {}, tunnelcfg);
}

function rdpClicked() {
    var data = readForm();
    var exepath = data['rdp'];
    var args = []
    if (process.platform == 'linux') {
        args = ['127.0.0.1:lport'];
    } else {
        args = ['/v:127.0.0.1:lport'];
    }
    var tunnelcfg = {
        nodeid: data["nodeidhex"],
        port: 3389
    };
    createPipeAndExec(exepath, args, {}, tunnelcfg);
}

function cmdClicked() {
    var data = readForm();
    var cmd_id = null;
    if (document.querySelector('input[name="select_cmd_radio"]:checked')!=null) {
        cmd_id = document.querySelector('input[name="select_cmd_radio"]:checked').value.substring(4);                
    } else {
        cmd_data["cmd_id"] = null;
        alert("No Command is selected.");
        return;
    } 
    var exepath = cmds[cmd_id].cmdexec;
    var args = cmds[cmd_id].cmdargs.trim().split(/\s+/);
    var tunnelcfg = {
        nodeid: data["nodeidhex"],
        port: cmds[cmd_id].cmdport
    };
    createPipeAndExec(exepath, args, {}, tunnelcfg);
}
