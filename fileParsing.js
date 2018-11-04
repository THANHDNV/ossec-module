#!/usr/bin/env node

const chokidar = require('chokidar');
const mongoClient = require('mongodb').MongoClient;
const util = require('util');
const fs = require('fs');
const mongoose = require('mongoose');

var url =  "mongodb://127.0.0.1:27017";
var globalCollection = "global";
var agentCollection = "%s_%s";

var ossecDir = "/var/ossec";
var filesAndDir = [ossecDir + "/etc/client.keys", ossecDir + "/queue/agent-info/"];

//init mongoose schema and model
mongoose.Promise = global.Promise;
const Schema = mongoose.Schema;
var agentInfoSchema = Schema({
  id: String,
  name: String,
  ip: String,
  key: String,
  os: String,
  os_arch: String,
  version: String,
  config_sum: String,
  lastAlive: Date
});
agentInfoSchema.index({"id": 1, "name": 1});
var agentInfoModel = mongoose.model("agent", agentInfoSchema, "agent");

// read files synchronously and get agent info
async function readFilesFirst() {
  filesAndDir.forEach((path, index) => {
    var isFile = false;;
    try {
      isFile = fs.statSync(path).isFile();
    } catch (error) {
      return;
    }
    if (isFile) {
      // client.keys
      try {
        var data = fs.readFileSync(path, 'utf8');

        //connect to db
        mongoose.connect(url + "/" + globalCollection);
        var db = mongoose.connection;

        db.on('error', err => console.log("Connection Error: " + err));
        db.once('open', () => {
          //process data
          var lines = data.toString().trim().split("\n");

          var validAgentList = [];

          async function pushToAgentList (doc) {
            
              validAgentList.push(doc);
            
          }

          async function addDocsToCollection (line) {
            var agentInfoArray = line.split(" ");
            var agentObj = {
              $setOnInsert: {
                id: agentInfoArray[0].toString().trim(),
                name: agentInfoArray[1].toString().trim(),
              },
              $set: {
                ip: agentInfoArray[2].toString().trim(),
                key: agentInfoArray[3].toString().trim(),
              }              
            };
            agentInfoModel.findOneAndUpdate({
              id: agentInfoArray[0].toString().trim(),
              name: agentInfoArray[1].toString().trim()},
              agentObj, {new: true, upsert: true}, (err, doc, res) => {
                if (err) {
                  console.log("Find and Update Error: " + err);
                } else {
                  // console.log("\n\n\nResult:")
                  // console.log(doc);
                  // console.log(res);
                  // console.log("\n\n\n\n");
                  // pushToAgentList(doc);
                }
              })
          }

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(lines, addDocsToCollection).then(() => {
            agentInfoModel.find({}).then((agentList) => {
              // console.log(agentList)
              // console.log()
              // console.log(validAgentList)
              // console.log()
              //filter before delete
              var filtered = agentList.filter(agent => {
                var found = validAgentList.find(vAgent => vAgent.id == agent.id && vAgent.name == agent.name);
                return typeof found === 'undefined'
              })
              // console.log(filtered);
  
              //delete
              filtered.forEach((agent) => {
                if (!(agent in validAgentList)) {
                  agentInfoModel.deleteOne(agent, err => console.log('Delete Error: ' + err));
                } else {
                }
              })
  
            }).then(() => {
              //close the database
              db.close();
            })
          })

          // delete agents not in client.keys
          
        })
      } catch (error) {
        console.log("File Reading Error: " + error)
      }
    } else {
      //other folders
      if (path.indexOf("/queue/agent-info") > -1) {
        //read each files in agent-info
        try {
          const path = require('path');
          const dirName = "/queue/agent-info/";
          var fileNames = fs.readdirSync(path.join(ossecDir, dirName), "utf8");

          async function updateagentInfoFromFile(filename) {
            var filePath = path.join(ossecDir, dirName, filename)
            var isFile = fs.statSync(filePath);
            if (isFile) {
              async function getOsArch(os) {
                return new Promise((res, rej) => {
                  var archs = [ "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", "" ]
                  for (i = 0; i < archs.length; i++) {
                    if (os.indexOf(archs[i]) > -1) {
                      res(archs[i]);
                    }
                  }
                })
              }

              var data = fs.readFileSync(filePath, 'utf8');
              var name = filename.split("-")[0];
              var ip = filename.split("-")[1];

              var os_arch = await getOsArch(data)
              var mTime = fs.statSync(filePath).mtime;
              var ossecVersionArr = data.split(" - ")[1].split(" / ").push("");
              var version = ossecVersionArr[0];
              var configSum = ossecVersionArr[1];

              //create update info obj
              var agentUpdateInfo = {
                $set: {
                  os: data,
                  os_arch: os_arch,
                  lastAlive: mTime,
                  version: version,
                  config_sum: configSum,
                },
                $setOnInsert: {
                  name: name,
                  ip: ip
                }
              }
              console.log(agentUpdateInfo)

              //connect to mongodb
              mongoose.connect(url + "/" + globalCollection);
              var db = mongoose.connection;
              db.on('err', err => Console.log("Connection Error: " + err))
              db.on("open", () => {
                agentInfoModel.findOneAndUpdate({
                  name: name,
                  ip: ip,
                }, agentUpdateInfo, {
                  new: true,
                  upsert: false
                }, (err, doc, res) => {
                  if (err) {
                    console.log("Update Error: " + err);
                  } else {
                    // console.log(doc)
                    // console.log(res)
                    // console.log();
                  }
                }).then(() => {
                  db.close();
                })
              })
            }
          }

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(fileNames, updateagentInfoFromFile);
        } catch (error) {
          console.log(error);
        }
      } else if (path.indexOf("/queue/rootcheck/") > -1) {

      } else if (path.indexOf("/queue/syscheck/") > -1) {
        
      }
    }
  })
}

// watcher will watch file asynchronously

async function watchFile(){

}

//calling main
async function main() {
  await readFilesFirst();
}
main();
var watcher = chokidar.watch(filesAndDir, {persistent: true});

watcher
  .on('add', function(fPath, stat) {
    console.log("File ", fPath, " has been added")
    if (fPath.indexOf("/queue/agent-info/") > -1) {
    //   var fPathArray = fPath.split("/");
    //   var fName = fPathArray[fPathArray.length - 1];
    //   var id = fName.split("_")[0];
    //   var name = fName.split("_")[1];

    //   var os_arch = "";
    //   function getOsArch(os) {        
    //     var archs = [ "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", "" ]
    //     archs.forEach(arch => {
    //       if (os.indexOf(arch) > -1) {os_arch = arch};
    //     })
    //   }

    //   // get agent info from file
      
    //   fs.readFile(fPath, 'utf8', (err, data) => {
    //     if (err) {
    //       console.log("File reading Error: " + err);
    //     } else {
    //       mongoose.connect(url);
    //       var db = mongoose.connection.useDb(globalCollection);
    //       db.on("error", err => console.log("Connection Error: " + err));
    //       db.on("open", () => {
    //         console.log("Connected to update")
    //         var agent = {}
    //         agent.os = data.trim();
    //         getOsArch(agent.os)
    //         agent.os_arch = os_arch;
    //         var ossecVersionArr = agent.os.split(" - ")[1].split(" / ").push("");
    //         agent.version = ossecVersionArr[0];
    //         agent.configSum = ossecVersionArr[1];
    //         agent.lastAlive = stat.mTime;
            
    //         console.log(agent);
    //         agentInfoModel.findOneAndUpdate({
    //           id: id,
    //           name: name,
    //         }, agent, (err, doc, res) => {
    //           if (err) {
    //             console.log("Update Err: " + err)
    //           } else {
    //             console.log(doc);
    //             console.log(res);
    //             console.log();
    //           }
    //         }).then((res) => {
    //           db.close();
    //         })          
    //       })
    //     }
    //   })
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {

    }
  })
  .on('change', function(fPath, stat) {
    // console.log('File', path, 'has been changed');
  })
  .on('unlink', function(fPath) {console.log('File', path, 'has been removed');})
  .on('error', function(error) {console.error('Error happened', error);})