"use strict";

const { MongoClient } = require("mongodb");
const { db: dbUri } = require("../config/config");

const defaultAdmin = {
    userName: "admin",
    firstName: "Node Goat",
    lastName: "Admin",
    password: "Admin_123",
    isAdmin: true
};

const defaultEmployees = [
    {
        userName: "user1",
        firstName: "John",
        lastName: "Doe",
        benefitStartDate: "2030-01-10",
        password: "User1_123"
    },
    {
        userName: "user2",
        firstName: "Will",
        lastName: "Smith",
        benefitStartDate: "2025-11-30",
        password: "User2_123"
    }
];

MongoClient.connect(dbUri, (connectError, db) => {
    if (connectError) {
        console.error("Unable to connect to MongoDB while ensuring the default admin", connectError);
        process.exit(1);
    }

    const users = db.collection("users");
    users.findOne({ userName: defaultAdmin.userName }, (findError, existingAdmin) => {
        if (findError) {
            console.error("Unable to look up the default admin", findError);
            db.close();
            process.exit(1);
        }

        users.find({}, { _id: 1 }).toArray((listError, userRecords) => {
            if (listError) {
                console.error("Unable to determine the next user ID", listError);
                db.close();
                process.exit(1);
            }

            const highestUserId = userRecords.reduce((highest, user) =>
                Number.isSafeInteger(user._id) ? Math.max(highest, user._id) : highest, 0);
            const adminId = existingAdmin ? existingAdmin._id : highestUserId + 1;
            const insertAdmin = callback => {
                if (existingAdmin) return callback(null);
                users.insert(Object.assign({ _id: adminId }, defaultAdmin), error => callback(error));
            };

            insertAdmin(insertError => {
                if (insertError) {
                    console.error("Unable to create the default admin", insertError);
                    db.close();
                    process.exit(1);
                }

                users.find({}, { _id: 1 }).toArray((updatedListError, updatedUserRecords) => {
                    if (updatedListError) {
                        console.error("Unable to determine the next user ID", updatedListError);
                        db.close();
                        process.exit(1);
                    }

                    let nextUserId = updatedUserRecords.reduce((highest, user) =>
                        Number.isSafeInteger(user._id) ? Math.max(highest, user._id) : highest, 0) + 1;
                    const seedEmployee = (index, callback) => {
                        if (index === defaultEmployees.length) return callback(null);

                        const employee = defaultEmployees[index];
                        users.findOne({ userName: employee.userName }, (employeeFindError, existingEmployee) => {
                            if (employeeFindError) return callback(employeeFindError);
                            if (existingEmployee) return seedEmployee(index + 1, callback);

                            users.insert(Object.assign({ _id: nextUserId++ }, employee), insertEmployeeError => {
                                if (insertEmployeeError) return callback(insertEmployeeError);
                                seedEmployee(index + 1, callback);
                            });
                        });
                    };

                    seedEmployee(0, seedError => {
                        if (seedError) {
                            console.error("Unable to create the default demo employees", seedError);
                            db.close();
                            process.exit(1);
                        }

                        db.collection("counters").update({ _id: "userId" }, {
                            $max: { seq: nextUserId - 1 }
                        }, { upsert: true }, counterError => {
                            db.close();
                            if (counterError) {
                                console.error("Unable to initialize the user ID counter", counterError);
                                process.exit(1);
                            }
                            console.log("Default admin and demo employees are ready");
                        });
                    });
                });
            });
        });
    });
});