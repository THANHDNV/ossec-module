#!/usr/bin/env node

const chokidar = require('chokidar');
const mongoClient = require('mongodb').MongoClient;
const util = require('util');
const fs = require('fs'), path = require('path');

console.log("Start");
var url =  "mongodb://127.0.0.1:27017";
var globalCollection = "global";
var agentCollection = "%s_%s";

var ossecDir = "/var/ossec";
var filesAndDir = [ossecDir + "/etc/client.keys", ossecDir + "/queue/agent-info/"];

var watcher = chokidar.watch(filesAndDir, {persistent: true});

watcher
  .on('add', function(path, stat) {
    console.log("File ", path, " has been added")
    if (path.indexOf("client.keys") > -1) {
      fs.readFile(path, (err, data) => {
        if (!err) {
          mongoClient.connect(url, {poolSize: 10}, (connectErr, db) => {
            if (connectErr) {
              console.log("Unable to connect to database");
            } else { 
              var dbo = db.db(globalCollection);
              dbo.createCollection("agent", (createColError, createColRes) => {
                // console.log(createColError);
                // console.log(createColRes);
                // db.close();
              })
              var managerObj = {
                id: "000",
              }

              dbo.collection("agent").findOne(managerObj, (findErr, findRes) => {
                if (findErr == null & findRes == null) {
                  dbo.collection("agent").insertOne(managerObj, (insertErr,  insertRes) => {
                    if (insertErr) {
                      console.log(insertErr);
                    } else {
                      console.log(insertRes);
                    }
                    // db.close();
                  })
                }
                // db.close();
              })

              dbo.collection("agent").createIndex({"id":  1}, {unique: true}, (indexErr, indexRes) => {
                if (indexErr) {
                  console.log(indexErr);
                } else {
                  console.log(indexRes);
                }
                // db.close();
              })

              var lines = data.toString().trim().split("\n");
              lines.forEach(line => {
                if (!(/^\s*$/.test(line))) {
                  var agentInfoArray = line.split(" ");
                  var agentObj = {
                    id: agentInfoArray[0].toString().trim(),
                    name: agentInfoArray[1].toString().trim(),
                    ip: agentInfoArray[2].toString().trim(),
                    hashed: agentInfoArray[3].toString().trim(),
                  }

                  dbo.collection("agent").insertOne(agentObj, (insErr, insRes) => {
                    if (insErr) {
                      var updateObj = { $set: {
                        name: agentInfoArray[1].toString().trim(),
                        ip: agentInfoArray[2].toString().trim(),
                        hashed: agentInfoArray[3].toString().trim(),
                      }}
                      dbo.collection("agent").updateOne({id: agentInfoArray[0].toString().trim()}, updateObj, (updErr, updRes) => {
                        if (updErr) {
                          console.log("Update Error");
                          console.log(updErr);
                        } else {
                          console.log("Updated");
                          console.log(updRes);
                        }
                        // db.close();
                      })
                    } else {
                      console.log("Inserted");
                      console.log(insRes);
                    }
                    // db.close();
                  })
                }
              })
              db.close();
            }
          })
          }
        })
    } else if (path.indexOf("/queue/agent-info/") > -1) {

    } else if (path.indexOf("/queue/rootcheck/") > -1) {

    } else if (path.indexOf("/queue/syscheck/") > -1) {

    } else {
      console.log("Something's not right");
    }
  })
  .on('change', function(path, stat) {
    // console.log('File', path, 'has been changed');
  })
  .on('unlink', function(path) {console.log('File', path, 'has been removed');})
  .on('error', function(error) {console.error('Error happened', error);})