/////////////////////////////////////////////////////////////
var WebSocket = require('ws');
var Protocol = require('pomelo-protocol');
var Package = Protocol.Package;
var Message = Protocol.Message;
var EventEmitter = require('events').EventEmitter;
var protocol = require('pomelo-protocol');
var protobuf = require('pomelo-protobuf');
var cwd = process.cwd();
var utils = require(cwd + '/app/script/utils');
var moveStat = require(cwd + '/app/script/statistic').moveStat;
var attackStat = require(cwd + '/app/script/statistic').attackStat;
var areaStat = require(cwd + '/app/script/statistic').areaStat;
var onlineStat = require(cwd + '/app/script/statistic').onlineStat;
var userId = require(cwd + '/app/script/statistic').userId;
var util = require('util');

if (typeof Object.create !== 'function') {
  Object.create = function (o) {
    function F() { }
    F.prototype = o;
    return new F();
  };
}

var JS_WS_CLIENT_TYPE = 'js-websocket';
var JS_WS_CLIENT_VERSION = '0.0.1';

var RES_OK = 200;
var RES_FAIL = 500;
var RES_OLD_CLIENT = 501;

if (typeof Object.create !== 'function') {
  Object.create = function (o) {
    function F() { }
    F.prototype = o;
    return new F();
  };
}

var root = {};
var pomelo = Object.create(EventEmitter.prototype); // object extend from object
root.pomelo = pomelo;
var socket = null;
var reqId = 0;
var callbacks = {};
var handlers = {};
//Map from request id to route
var routeMap = {};

var heartbeatInterval = 0;
var heartbeatTimeout = 0;
var nextHeartbeatTimeout = 0;
var gapThreshold = 100;   // heartbeat gap threashold
var heartbeatId = null;
var heartbeatTimeoutId = null;

var handshakeCallback = null;

var handshakeBuffer = {
  'sys': {
    type: JS_WS_CLIENT_TYPE,
    version: JS_WS_CLIENT_VERSION
  },
  'user': {
  }
};

var initCallback = null;

pomelo.init = function (params, cb) {
  initCallback = cb;
  var host = params.host;
  var port = params.port;

  var url = 'ws://' + host;
  if (port) {
    url += ':' + port;
  }

  handshakeBuffer.user = params.user;
  handshakeCallback = params.handshakeCallback;
  initWebSocket(url, cb);
};

var initWebSocket = function (url, cb) {
  console.log('connect to ' + url);
  var onopen = function (event) {
    var obj = Package.encode(Package.TYPE_HANDSHAKE, Protocol.strencode(JSON.stringify(handshakeBuffer)));
    send(obj);
  };
  var onmessage = function (event) {
    processPackage(Package.decode(event.data), cb);
    // new package arrived, update the heartbeat timeout
    if (heartbeatTimeout) {
      nextHeartbeatTimeout = Date.now() + heartbeatTimeout;
    }
  };
  var onerror = function (event) {
    pomelo.emit('io-error', event);
    console.error('socket error: ', event);
  };
  var onclose = function (event) {
    console.error('socket close: ', event.type);
    pomelo.emit('close', event);
  };
  socket = new WebSocket(url);
  socket.binaryType = 'arraybuffer';
  socket.onopen = onopen;
  socket.onmessage = onmessage;
  socket.onerror = onerror;
  socket.onclose = onclose;
};

pomelo.disconnect = function () {
  if (socket) {
    if (socket.disconnect) socket.disconnect();
    if (socket.close) socket.close();
    console.log('disconnect');
    socket = null;
  }

  if (heartbeatId) {
    clearTimeout(heartbeatId);
    heartbeatId = null;
  }
  if (heartbeatTimeoutId) {
    clearTimeout(heartbeatTimeoutId);
    heartbeatTimeoutId = null;
  }
};

pomelo.request = function (route, msg, cb) {
  if (arguments.length === 2 && typeof msg === 'function') {
    cb = msg;
    msg = {};
  } else {
    msg = msg || {};
  }
  route = route || msg.route;
  if (!route) {
    return;
  }

  reqId++;
  sendMessage(reqId, route, msg);

  callbacks[reqId] = cb;
  routeMap[reqId] = route;
};

pomelo.notify = function (route, msg) {
  msg = msg || {};
  sendMessage(0, route, msg);
};

var sendMessage = function (reqId, route, msg) {
  var type = reqId ? Message.TYPE_REQUEST : Message.TYPE_NOTIFY;

  //compress message by protobuf
  var protos = !!pomelo.data.protos ? pomelo.data.protos.client : {};
  if (!!protos[route]) {
    msg = protobuf.encode(route, msg);
  } else {
    msg = Protocol.strencode(JSON.stringify(msg));
  }


  var compressRoute = 0;
  if (pomelo.dict && pomelo.dict[route]) {
    route = pomelo.dict[route];
    compressRoute = 1;
  }

  msg = Message.encode(reqId, type, compressRoute, route, msg);
  var packet = Package.encode(Package.TYPE_DATA, msg);
  send(packet);
};

var send = function (packet) {
  //socket.send(packet.buffer);
  socket.send(packet, { binary: true, mask: true });
};


var handler = {};

var heartbeat = function (data) {
  if (!heartbeatInterval) {
    // no heartbeat
    return;
  }

  var obj = Package.encode(Package.TYPE_HEARTBEAT);
  if (heartbeatTimeoutId) {
    clearTimeout(heartbeatTimeoutId);
    heartbeatTimeoutId = null;
  }

  if (heartbeatId) {
    // already in a heartbeat interval
    return;
  }

  heartbeatId = setTimeout(function () {
    heartbeatId = null;
    send(obj);

    nextHeartbeatTimeout = Date.now() + heartbeatTimeout;
    heartbeatTimeoutId = setTimeout(heartbeatTimeoutCb, heartbeatTimeout);
  }, heartbeatInterval);
};

var heartbeatTimeoutCb = function () {
  var gap = nextHeartbeatTimeout - Date.now();
  if (gap > gapThreshold) {
    heartbeatTimeoutId = setTimeout(heartbeatTimeoutCb, gap);
  } else {
    console.error('server heartbeat timeout');
    pomelo.emit('heartbeat timeout');
    pomelo.disconnect();
  }
};

var handshake = function (data) {
  data = JSON.parse(Protocol.strdecode(data));
  if (data.code === RES_OLD_CLIENT) {
    pomelo.emit('error', 'client version not fullfill');
    return;
  }

  if (data.code !== RES_OK) {
    pomelo.emit('error', 'handshake fail');
    return;
  }

  handshakeInit(data);

  var obj = Package.encode(Package.TYPE_HANDSHAKE_ACK);
  send(obj);
  if (initCallback) {
    initCallback(socket);
    initCallback = null;
  }
};

var onData = function (data) {
  //probuff decode
  var msg = Message.decode(data);

  if (msg.id > 0) {
    msg.route = routeMap[msg.id];
    delete routeMap[msg.id];
    if (!msg.route) {
      return;
    }
  }

  msg.body = deCompose(msg);

  processMessage(pomelo, msg);
};

var onKick = function (data) {
  pomelo.emit('onKick');
};

handlers[Package.TYPE_HANDSHAKE] = handshake;
handlers[Package.TYPE_HEARTBEAT] = heartbeat;
handlers[Package.TYPE_DATA] = onData;
handlers[Package.TYPE_KICK] = onKick;

var processPackage = function (msg) {
  handlers[msg.type](msg.body);
};

var processMessage = function (pomelo, msg) {
  if (!msg.id) {
    // server push message
    pomelo.emit(msg.route, msg.body);
    return;
  }

  //if have a id then find the callback function with the request
  var cb = callbacks[msg.id];

  delete callbacks[msg.id];
  if (typeof cb !== 'function') {
    return;
  }

  cb(msg.body);
  return;
};

var processMessageBatch = function (pomelo, msgs) {
  for (var i = 0, l = msgs.length; i < l; i++) {
    processMessage(pomelo, msgs[i]);
  }
};

var deCompose = function (msg) {
  var protos = !!pomelo.data.protos ? pomelo.data.protos.server : {};
  var abbrs = pomelo.data.abbrs;
  var route = msg.route;

  //Decompose route from dict
  if (msg.compressRoute) {
    if (!abbrs[route]) {
      return {};
    }

    route = msg.route = abbrs[route];
  }
  if (!!protos[route]) {
    return protobuf.decode(route, msg.body);
  } else {
    return JSON.parse(Protocol.strdecode(msg.body));
  }

  // return msg;
};

var handshakeInit = function (data) {
  if (data.sys && data.sys.heartbeat) {
    heartbeatInterval = data.sys.heartbeat * 1000;   // heartbeat interval
    heartbeatTimeout = heartbeatInterval * 2;        // max heartbeat timeout
  } else {
    heartbeatInterval = 0;
    heartbeatTimeout = 0;
  }

  initData(data);

  if (typeof handshakeCallback === 'function') {
    handshakeCallback(data.user);
  }
};

//Initilize data used in pomelo client
var initData = function (data) {
  if (!data || !data.sys) {
    return;
  }
  pomelo.data = pomelo.data || {};
  var dict = data.sys.dict;
  var protos = data.sys.protos;

  //Init compress dict
  if (dict) {
    pomelo.data.dict = dict;
    pomelo.data.abbrs = {};

    for (var route in dict) {
      pomelo.data.abbrs[dict[route]] = route;
    }
  }

  //Init protobuf protos
  if (protos) {
    pomelo.data.protos = {
      server: protos.server || {},
      client: protos.client || {}
    };
    if (!!protobuf) {
      protobuf.init({ encoderProtos: protos.client, decoderProtos: protos.server });
    }
  }
};


/////////////////////////////////////////////////////////////

// var queryHero = require(cwd + '/app/data/mysql').queryHero;
var envConfig = require(cwd + '/app/config/env.json');
var config = require(cwd + '/app/config/' + envConfig.env + '/config');
var mysql = require('mysql');

pomelo.player = null;
pomelo.uid = null;

var client = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  port: 3306,
  password: 'nds3.14!',
  database: 'Pomelo'
});

var START = 'start';
var END = 'end';
var INCR = 'incr';
var DECR = 'decr';
var DirectionNum = 8;

var EntityType = {
  PLAYER: 'player',
  NPC: 'npc',
  MOB: 'mob',
  EQUIPMENT: 'equipment',
  ITEM: 'item'
};

var ActFlagType = {
  ENTRY: 0,
  ENTER_SCENE: 1,
  ATTACK: 2,
  MOVE: 3,
  PICK_ITEM: 4,
  ON_LINE: 5,
  MATCH: 6,
  ENTER_GAME: 7,
  CHAT: 8
};

var monitor = function (type, name, reqId) {
  if (typeof actor !== 'undefined') {
    actor.emit(type, name, reqId);
  } else {
    console.error(Array.prototype.slice.call(arguments, 0));
  }
}

var connected = false;

var offset = (typeof actor !== 'undefined') ? actor.id : 1;

if (typeof actor !== 'undefined') {
  console.log(offset + ' ' + actor.id);
}

// temporary code
// queryHero(client, 1, offset, function(error, users){
// queryHero(client, 1, 0, function (error, users) {
//   // temporary code
//   console.log('QueryHero ~ offset = ', offset);
//   var user = users[0];
//   client.end();
//   // monitor(START, 'enterScene', ActFlagType.ENTER_SCENE);
//   console.log('QueryHero is running ...');
//   console.log('QueryHero ~ user = ', JSON.stringify(user));
//   if (user) {
//     queryEntry(user.uid, function (host, port) {
//       entry(host, port, user.token, function () {
//         connected = true;
//       });
//     });
//   }
// });
var crypto = require('crypto');
var create= function(uid, timestamp) {
    var msg = uid + '|' + timestamp;
    var cipher = crypto.createCipher('aes256', "pomelo_test_master");
    var enc = cipher.update(msg, 'utf8', 'hex');
    enc += cipher.final('hex');
    return enc;
};

var __u = 0;
function queryEntry() {
    //4901182
    console.log("----------------------------"+userId.total)
    var uid = 1000+(userId.total++);
    __u = uid;
    // var uid = Math.floor(Math.random() * 100000)+1000;
    var token = create(uid, Date.now() / 1000)

    pomelo.init({
        host: "172.16.185.86",
        port: 3014,
        log: true
    }, function () {
        monitor(START, 'online', ActFlagType.ON_LINE);

        // 连接成功之后，向gate服务器请求ip和port
        var route = "gate.gateHandler.queryEntry";
        pomelo.request(route, {
            token: token,
            imei: uid + ""
        }, function (data) {
            var connector = data
            // 断开与gate服务器之间的连接
            pomelo.disconnect();
            if (data.code === 500) {
                console.log("error")
            }
            //第二次
            // 使用gate服务器返回的ip和port请求连接connector服务器
            pomelo.init({
                host: connector.host,
                port: connector.port,
                log: true,
            }, function () {
                // 连接成功之后,向connector服务器发送登录请求
                pomelo.request("connector.entryHandler.enter", {
                    token: token,
                    islogin: 1,
                    flag: "A",
                    imei: "1",
                    device: "pro",
                    icon: "icon3333",
                    nickname: "name222"
                }, function (data) {
                    if (data.code === 200) {
                        pomelo.disconnect();
                        connector.port = data.port
                        connector.host = data.host
                        connector.uid = data.uid
                        console.log("uid       " + data.uid)
                        setTimeout(function () {
                                pomelo.init({
                                    port: connector.port,
                                    host: connector.host,
                                    log: true
                                }, function () {
                                    // 连接成功之后,向connector服务器发送登录请求
                                    pomelo.request("connector.entryHandler.enter2", {
                                        uid: connector.uid,
                                        token: data.token
                                    }, function (data) {
                                        //出现在统计输入框
                                        monitor(INCR, 'online', ActFlagType.ON_LINE);
                                        onlineStat.total++;
                                        monitor(END, 'online', ActFlagType.ON_LINE);
                                        //匹配
                                        setTimeout(function () {
                                            monitor(START, 'match', ActFlagType.MATCH);
                                            var __gid = [1997,14,15,16];
                                            //计算传入游戏的数量
                                            var gameNum = Math.floor(Math.random() * 3)+1
                                            //计算游戏的顺序
                                            var firstGame = Math.floor(Math.random() * 4)
                                            var games = [];
                                            for (var g in __gid) {
                                                var __g = parseInt(g)
                                                if ((__g === firstGame) && __g !== 0) {
                                                    continue;
                                                }
                                                if (games.length === 0) {
                                                    games.push(__gid[firstGame])
                                                } else {
                                                    games.push(__gid[g])
                                                }
                                                if ((__g + 1) === gameNum) {
                                                    console.log("break...")
                                                    break;
                                                }
                                            }
                                            pomelo.request("connector.matchEntryHandler.match", {
                                                gid: games,
                                                cmd: 1,
                                                imei: "2323232434334",
                                                num: 2
                                            }, function (data) {
                                              if(data.code === 200){
                                                  monitor(INCR, 'randomMatchSuc', ActFlagType.MATCH);
                                              }else if(data.code===4006 || data.code===4008){
                                                  monitor(INCR, 'randomMatchWait', ActFlagType.MATCH);
                                              }else {
                                                  monitor(INCR, 'randomMatchFail', ActFlagType.MATCH);
                                              }
                                                monitor(END, 'match', ActFlagType.MATCH);
                                            });
                                        }, 0)
                                    });
                                });
                            }
                            , 0)
                    }
                });
            });
        });
    });
}

pomelo.on('disconnect', function (reason) {
    monitor(INCR, 'disconnect', ActFlagType.ON_LINE);
});

pomelo.on('close', function (reason) {
    console.log("close.................")
    monitor(INCR, 'close', ActFlagType.ON_LINE);
});

pomelo.on('onMatch', function (data) {
    /**
     * { code: 200,
  room: 1170,
  game: 14,
  userInfo:
   [ { birth: '19900018',
       icon: 'http://img.res.meizu.com/img/download/uc/11/35/22/19/60/113522196/w200h200?t=1531361414000',
       id: 1000,
       name: 'For_Someone_必应必应必应必应必应',
       sex: 2,
       type: 1 },
     { birth: '',
       icon: 'http://img.res.meizu.com/img/download/uc/76/80/76/40/00/7680764/w200h200?t=1511762994000',
       id: 1001,
       name: '用户30723056',
       sex: 0,
       type: 1 } ] }
     */

    if(data.code !== 200){
        return;
    }
    //匹配成功之后，双发调用进入游戏接口并发送10次消息给对方
    setTimeout(function () {
        monitor(START, 'enterGame', ActFlagType.ENTER_GAME);
            pomelo.request("connector.gameHandler.enter", {
            game:data.game,
            cmd:1,
            rid:data.room,
            token:create(__u, Date.now() / 1000),
            islogin:1,
            flag:"A",
            imei:"dsfdffddf",
            num:2
        }, function (data) {
        if (data.code === 200){
            monitor(END, 'enterGame', ActFlagType.ENTER_GAME);
            monitor(INCR, 'enterGameSuc', ActFlagType.MATCH);
            console.log("进入游戏成功")
            //进入游戏成功后过10秒给对方发消息发10次
            setTimeout(function () {
                for(var i = 0;i<10;i++){
                    //一次性发送太多会阻塞 导致下线
                    monitor(START, 'pk', ActFlagType.CHAT);
                    pomelo.request("chat.gameHandler.chat", {msg:"扶贫,党员,干部,修宪,中央,纪委,十九大,干部,习近平,李克强,栗战书,汪洋,王沪宁,赵乐际,韩正,国务院,共产党,党章,人大,两会,国民党,共产,毛泽东,毛主席,周恩来,朱德,彭德怀,林彪,刘伯承,贺龙,陈毅,罗荣桓,徐向前,聂荣臻,叶剑英,蒋介石,刘少奇,邓小平,四人帮,文革,江泽民,宪法,薄熙来,周永康,郭伯雄,孙政才,徐才厚,苏荣,周本顺,杨栋梁,苏树林,蒋洁敏,李东生,杨金山,令计划,项俊波,王三运,杨焕宁,吴爱英,张阳,房峰辉,杨晶,李春城,王永春,万庆良,陈川平,潘逸阳,朱明国,王敏,杨卫泽,范长秘,仇和,余远辉,吕锡文,李云峰,牛志忠,杨崇勇,张喜武,莫建成,孙怀山,夏兴华,虞海燕,李立国,窦玉沛,王银成,杨东平,李文科,陈旭,张化为,陈传书,周春雨,魏民洲,杨家才,刘新齐,曲淑辉,刘善桥,张喜武,王宏江,周化辰,许前飞,杨焕宁,李刚,夏崇源,何挺,沐华平,鲁炜,刘强,张杰辉,党的领导,改革,中国特色社会主义,法治建设,法制建设,核心价值观,中共中央,人民代表大会,中国共产党,检查委员会,中央委员会,新时代,党和国家,中华民族伟大复兴,中央委员,常委,纲领,领导人中国梦,依法治国,法治中国,从严治党,基本国策,全会,丁薛祥,王晨,王沪宁,刘鹤,许其亮,孙春兰,李希,李强,李鸿忠,杨洁篪,杨晓渡,汪洋,张又侠,陈希,陈全国,陈敏尔,赵乐际,胡春华,郭声琨,黄坤明,蔡奇, 马凯,王岐山,刘云山,刘延东,刘奇葆,许其亮,孙春兰,孙政才,杨晓渡,尤权,魏凤和,李作成,苗华,张升民,李建国,李源潮,张春贤,张高丽,张德江,范长龙,孟建柱,赵乐际,胡春华,俞正声,郭金龙,习仲勋,十九届三中全会,违纪,撤职,处分,打虎",imei:"343"},
                        function (data) {
                            monitor(END, 'pk', ActFlagType.CHAT);
                        if(data.code === 200){
                            monitor(INCR, 'pkSuc', ActFlagType.CHAT);
                        }else {
                            monitor(INCR, 'pkFail', ActFlagType.CHAT);
                        }
                });
                }
            },10*__u)
        }else {
            monitor(INCR, 'enterGameFail', ActFlagType.MATCH);
        }
    });
    },100)

});

queryEntry();

function entry(host, port, token, callback) {
  _host = host;
  _port = port;
  _token = token;
  if (!!socket) {
    return;
  }
  // 初始化socketClient
  pomelo.init({ host: host, port: port, log: true }, function () {
    // monitor(START, 'entry', ActFlagType.ENTRY);
    pomelo.request('connector.entryHandler.entry', { token: token }, function (data) {
      // monitor(END, 'entry', ActFlagType.ENTRY);
      if (callback) {
        callback(data.code);
      }

      if (data.code == 1001) {
        console.log('Login fail!');
        return;
      } else if (data.code == 1003) {
        console.log('Username not exists!');
        return;
      }

      if (data.code != 200) {
        console.log('Login Fail!');
        return;
      }

      afterLogin(pomelo, data);
    });
  });
}

var afterLogin = function (pomelo, data) {
  pomelo.player = null;
  pomelo.players = {};
  pomelo.entities = {};
  pomelo.isDead = false;
  pomelo.lastAttack = null;
  var fightedMap = {};

  pomelo.on('onKick', function () {
    console.log('You have been kicked offline for the same account login in other place.');
  });

  pomelo.on('disconnect', function (reason) {
    console.log('disconnect invoke!' + reason);
  });

  var msgTempate = { scope: 'D41313', content: 'Kill ~' };
  /**
   * 处理登录请求
   */
  var login = function (data) {
    var player = data.player;
    if (player.id <= 0) {
      console.log("User is invalid! data = %j", data);
    } else {
      pomelo.uid = player.userId;
      pomelo.player = player;
      msgTempate.uid = pomelo.uid;
      msgTempate.playerId = pomelo.player.id;
      msgTempate.from = pomelo.player.name;
      msgTempate.areaId = pomelo.player.areaId;
      setTimeout(function () {
        enterScene();
      }, 0);
    }
  };

  login(data);

  var enterScene = function () {
    var msg = { uid: pomelo.uid, playerId: pomelo.player.id, areaId: pomelo.player.areaId };
    // monitor(START, 'enterScene', ActFlagType.ENTER_SCENE);
    pomelo.request("area.playerHandler.enterScene", msg, enterSceneRes);
    console.log('1 ~ EnterScene ~ areaId = %d, playerId = %d, name = %s',
      pomelo.player.areaId, pomelo.player.id, pomelo.player.name);
  }

  var enterSceneRes = function (data) {
    // monitor(END, 'enterScene', ActFlagType.ENTER_SCENE);
    pomelo.player = data.curPlayer;
    pomelo.addEntity(pomelo.player);

    for (var key in data.entities) {
      if (key !== EntityType.NPC) {
        var array = data.entities[key];
        for (var i = 0; i < array.length; i++) {
          var entity = array[i];
          entity.type = key;
          pomelo.addEntity(entity);
        }
      }
    }

    /*
    var start = 0
      , end = 0;
    start = new Date().getTime();
    console.log('\n\n' + 'start = ', start);
    // create instance testing
    var cnt = 10;
    pomelo.request("area.playerHandler.createInstance", {cnt: cnt}, function(args) {
      end = new Date().getTime();
      console.log('end = ', end);
      console.log('CreateInstance ~ args = ', JSON.stringify(args));
      // 計算花多久時間
      var tmpStr = util.format('CreateInstance(cnt=%j) cost time : %j sec\n\n', cnt, (end - start)/1000)
      console.log(tmpStr);
      process.exit(0);
    });
    */

    var actRandom = Math.floor(Math.random() * 2 + 1);
    var intervalTime = Math.floor(Math.random() * 3000 + 2000);
    if (actRandom === 1) {
      setInterval(function () {
        moveEvent();
      }, intervalTime);
      console.log('2 ~ EnterSceneRes ~ areaId = %d, playerId = %d, mover = %s, intervalTime = %d',
        pomelo.player.areaId, pomelo.player.id, pomelo.player.name, intervalTime);
    } else {
      setInterval(function () {
        attackEvent();
      }, intervalTime);
      console.log('2 ~ EnterSceneRes ~ areaId = %d, playerId = %d, fighter = %s, intervalTime = %d',
        pomelo.player.areaId, pomelo.player.id, pomelo.player.name, intervalTime);
    }

    /*
    setInterval(function() {
      moveEvent();
    }, intervalTime);
    console.log('2 ~ EnterSceneRes ~ areaId = %d, playerId = %d, mover = %s, intervalTime = %d',
      pomelo.player.areaId, pomelo.player.id, pomelo.player.name, intervalTime);
    setInterval(function() {
      attackEvent();
    }, intervalTime);
    console.log('2 ~ EnterSceneRes ~ areaId = %d, playerId = %d, fighter = %s, intervalTime = %d',
      pomelo.player.areaId, pomelo.player.id, pomelo.player.name, intervalTime);
    */
  }

  var sendChat = function () {
    pomelo.request('chat.chatHandler.send', msgTempate, okRes);
  }

  /**
   * 处理用户离开请求
   */
  pomelo.removePlayer = function (playerId) {
    var entityId = this.players[playerId];
    if (!!entityId) {
      this.removeEntity(entityId);
    }
  };

  pomelo.on('onUserLeave', function (data) {
    var playerId = data.playerId;
    this.removePlayer(playerId);
  });

  /**
   * 处理用户攻击请求
   */
  pomelo.on('onAttack', function (data) {
    if (data.result.result === 2) {
      var attackId = parseInt(data.attacker);
      var targetId = parseInt(data.target);
      var selfId = parseInt(pomelo.player.entityId);
      if (attackId === selfId || targetId === selfId) {
        if (targetId !== selfId) {
          clearAttack();
          pomelo.isDead = false;
          this.removeEntity(targetId);
        } else {
          pomelo.isDead = true;
          clearAttack();
        }
      } else {
        if (!!pomelo.lastAttAck && targetId === pomelo.lastAttAck.entityId) {
          clearAttack();
        }
        this.removeEntity(targetId);
      }
    }
  });

  pomelo.on('onRevive', function (data) {
    if (data.entityId === pomelo.player.entityId) {
      pomelo.isDead = false;
      clearAttack();
    } else {
      this.addEntity(data.entity);
    }
  });

  pomelo.on('onUpgrade', function (data) {
    msgTempate.content = 'Upgrade to ' + data.player.level + '!';
    sendChat();
  });

  pomelo.on('onDropItems', function (data) {
    var items = data.dropItems;
    var length = items.length;
    for (var i = 0; i < length; i++) {
      this.addEntity(items[i]);
    }
  });

  pomelo.on('onMove', function (data) {
    // console.log("OnMove ~ data = %j", data);
    var entity = pomelo.entities[data.entityId];
    if (!entity) {
      return;
    }
    if (data.entityId === pomelo.player.entityId) {
      var path = data.path[1];
      pomelo.player.x = path.x;
      pomelo.player.y = path.y;
      // console.log('self %j move to x=%j, y=%j', pomelo.uid, path.x, path.y);
    }
  });

  var moveDirection = Math.floor(Math.random() * DirectionNum + 1);

  var getPath = function () {
    var FIX_SPACE = Math.floor(Math.random() * pomelo.player.walkSpeed + 1);
    var startX = pomelo.player.x;
    var startY = pomelo.player.y;
    var endX = startX;
    var endY = startY;
    moveDirection = (++moveDirection % DirectionNum) ? moveDirection : 1;
    switch (moveDirection) {
      case 1:
        endX += FIX_SPACE;
        break;
      case 2:
        endX += FIX_SPACE;
        endY += FIX_SPACE;
        break;
      case 3:
        endY += FIX_SPACE;
        break;
      case 4:
        endX -= FIX_SPACE;
        endY += FIX_SPACE;
        break;
      case 5:
        endX -= FIX_SPACE;
        break;
      case 6:
        endX -= FIX_SPACE;
        endY -= FIX_SPACE;
        break;
      case 7:
        endY -= FIX_SPACE;
        break;
      case DirectionNum:
      default:
        endX += FIX_SPACE;
        endY -= FIX_SPACE;
        break;
    }
    var path = [{ x: startX, y: startY }, { x: endX, y: endY }];
    return path;
  }

  var getFirstFight = function () {
    var entities = pomelo.entities;
    var keyArray = Object.keys(entities);
    var len = keyArray.length;
    // console.log('entities.length = ', len);
    var randomNum = Math.floor(Math.random() * len);
    // console.log('randomNum = ', randomNum)
    var entity = entities[keyArray[randomNum]];
    // console.log('entity = ', entity)
    if (!entity) {
      for (var i = 0; i < entities.length; i++) {
        console.log('i = %j, entities[i] = %j', i, entities[i]);
      }
    }
    return entity;
  }

  var okRes = function () {

  }

  var moveEvent = function () {
    if (!!pomelo.isDead) { return; }
    var paths = getPath();
    var msg = { path: paths };
    monitor('incr', 'moveReq');
    monitor(START, 'move', ActFlagType.MOVE);
    pomelo.request('area.playerHandler.move', msg, function (data) {
      monitor(END, 'move', ActFlagType.MOVE);
      if (data.code !== RES_OK) {
        console.error('wrong path! %s %j : %d~%s, in area %d',
          Date(), msg, pomelo.player.id, pomelo.player.name, pomelo.player.areaId);
        return;
      }
      pomelo.player.x = paths[1].x;
      pomelo.player.y = paths[1].y;

      if (!moveStat.idDict[pomelo.player.id]) {
        moveStat.idDict[pomelo.player.id] = true;
        moveStat.total++;
      }
      console.log('Total mover num = %j', moveStat.total);

      areaStat.idDict[pomelo.player.areaId] = areaStat.idDict[pomelo.player.areaId] || {};
      var tmpDict = areaStat.idDict[pomelo.player.areaId];
      if (!tmpDict[pomelo.player.id]) {
        tmpDict[pomelo.player.id] = true;
        tmpDict.total = tmpDict.total || 0;
        tmpDict.total++;
      }
      console.log('In area = %j, total mover num = %j\n', pomelo.player.areaId, tmpDict.total);

      console.log('%s : %d~%s is moving, in area %d, pos(%d, %d)',
        Date(), pomelo.player.id, pomelo.player.name,
        pomelo.player.areaId, pomelo.player.x, pomelo.player.y);
    });
  };

  var attackEvent = function () {
    if (!pomelo.player.entityId || !!pomelo.isDead) {
      return;
    }
    var entity = pomelo.lastAttAck;
    if (!!entity) {
      doAttack(entity);
      var count = fightedMap[entity.entityId] || 1;
      fightedMap[entity.entityId] = count + 1;
      if (count >= 10) {
        delete fightedMap[entity.entityId];
        clearAttack();
      }
    } else {
      doAttack(getFirstFight());
    }
  };

  var doAttack = function (entity) {
    if (!entity) {
      return;
    }
    if (entity.type === EntityType.MOB || entity.type === EntityType.PLAYER) {
      if (entity.died) {
        return;
      }
      pomelo.lastAttAck = entity;

      var attackId = entity.entityId;
      var route = 'area.fightHandler.attack';
      var msg = { targetId: attackId };
      monitor('incr', 'attackReq');
      monitor(START, 'attack', ActFlagType.ATTACK);
      // pomelo.notify(route, msg);
      pomelo.request(route, msg, function () {
        monitor(END, 'attack', ActFlagType.ATTACK);
        console.log('\nTotal attacker num = %j', attackStat.total);
      });

      if (!attackStat.idDict[pomelo.player.id]) {
        attackStat.idDict[pomelo.player.id] = true;
        attackStat.total++;
      }
      // console.log('\nTotal attacker num = %j', attackStat.total);

      areaStat.idDict[pomelo.player.areaId] = areaStat.idDict[pomelo.player.areaId] || {};
      var tmpDict = areaStat.idDict[pomelo.player.areaId];
      if (!tmpDict[pomelo.player.id]) {
        tmpDict[pomelo.player.id] = true;
        tmpDict.total = tmpDict.total || 0;
        tmpDict.total++;
      }
      console.log('In area = %j, total attacker num = %j\n', pomelo.player.areaId, tmpDict.total);

      console.log('%s : %d~%s attack %d, in area %d, pos(%d, %d)',
        Date(), pomelo.player.id, pomelo.player.name, entity.entityId,
        pomelo.player.areaId, pomelo.player.x, pomelo.player.y);
    } else if (entity.type === EntityType.ITEM || entity.type === EntityType.EQUIPMENT) {
      var route = 'area.playerHandler.pickItem';
      var attackId = entity.entityId;
      // var msg = { areaId:pomelo.player.areaId, playerId:pomelo.player.id, targetId:attackId};
      var msg = { areaId: pomelo.player.areaId, playerId: pomelo.player.id, targetId: attackId };
      monitor(START, 'pickItem', ActFlagType.PICK_ITEM);
      pomelo.request(route, msg, function () {
        monitor(END, 'pickItem', ActFlagType.PICK_ITEM);
      });
    }
  }

  pomelo.on('onPickItem', function (data) {
    clearAttack();
    this.removeEntity(data.item);
    var item = pomelo.entities[data.item];
    if (!!item && data.player === pomelo.player.entityId) {
      msgTempate.content = 'I got a ' + item.kindName;
      sendChat(msgTempate);
    }
    if (item) {
      delete item;
    }
  });

  pomelo.on('onRemoveItem', function (data) {
    clearAttack();
    delete pomelo.entities[data.entityId];
  });

  ///////////////////////////////////////////////////////////////////
  pomelo.on('onAddEntities', function (data) {
    var entities = data;
    for (var key in entities) {
      var array = entities[key];
      for (var i = 0; i < array.length; i++) {
        var entity = array[i];
        entity.type = key;
        this.addEntity(entity);
        /*
        if(!this.getEntity(array[i].entityId)) {
          var entity = array[i];
          entity.type = key;
          this.addEntity(entity);
        }else{
          console.warn('add exist entity!');
        }
        */
      }
    }
  });

  /**
   * Handle remove entities message
   * @param data {Object} The message, contains entitiy ids to remove
   */
  pomelo.on('onRemoveEntities', function (data) {
    var entities = data.entities;
    for (var i = 0; i < entities.length; i++) {
      if (entities[i] !== pomelo.player.entityId) {
        this.removeEntity(entities[i]);
      }
    }
  });

  pomelo.getEntity = function (id) {
    return this.entities[id];
  };

  pomelo.addEntity = function (entity) {
    if (!entity || !entity.entityId) {
      return false;
    }
    switch (entity.type) {
      case EntityType.PLAYER: {
        if (!!entity.id) {
          pomelo.players[entity.id] = entity.entityId;
          pomelo.entities[entity.entityId] = { entityId: entity.entityId, playerId: entity.id, type: entity.type };
          return true;
        }
      }
        break;
      case EntityType.MOB:
      case EntityType.ITEM:
      case EntityType.EQUIPMENT: {
        pomelo.entities[entity.entityId] = { entityId: entity.entityId, type: entity.type };
        return true;
      }
        break;
    }
    return false;
  };

  /**
   * Remove entity from area
   * @param id {Number} The entity id or the entity to remove.
   * @api public
   */
  pomelo.removeEntity = function (id) {
    if (!pomelo.entities[id]) {
      return false;
    }

    delete pomelo.entities[id];
  };

  ////////////////////////////////////////////////////////////////////////

  var clearAttack = function () {
    pomelo.lastAttAck = null;
  }

};

