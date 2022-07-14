'use strict';

const { USERS_DB_NAME , REGION, PROFILE} = process.env
const AWS = require('aws-sdk');
const uuidv4 = require('uuid/v4');

const config = {
    region: AWS.config.region || REGION || 'us-west-2',
    validate: false
};

if (PROFILE) {
    const credentials = new AWS.SharedIniFileCredentials({ profile: PROFILE });
    Object.assign(config, {credentials});
}


const dynamodb = new AWS.DynamoDB.DocumentClient(config);

const saveUser = (profile) => {
    let id = uuidv4();
    profile.isActive = 1;
    profile.userId = id;
    const params = {
        TableName: USERS_DB_NAME,
        Item: profile
    };
    return dynamodb.put(params).promise();
};

const updateUser = (profile) => {
    const params = {
        TableName: USERS_DB_NAME,
        Item: profile
    };
    return dynamodb.put(params).promise();
};


const findUserByEmail = (email, site) => {
    console.log(USERS_DB_NAME)
    const params = {
        TableName : USERS_DB_NAME,
        IndexName: 'email_global_index',
        KeyConditionExpression: 'email = :email and site = :site',
        FilterExpression: 'isActive = :isActive',
        ExpressionAttributeValues: {
            ':email': email,
            ':site': site,
            ':isActive': 1
        }
    };
    return dynamodb.query(params, function onQuery(err, data){
        return data;
    }).promise();
};


const findUserByToken = (emailVerifyToken,site) => {
    const params = {
        TableName : USERS_DB_NAME,
        IndexName: 'email_verify_token_global_index',
        KeyConditionExpression: 'emailVerifyToken = :emailVerifyToken and site = :site',
        FilterExpression: 'isActive = :isActive',
        ExpressionAttributeValues: {
            ':emailVerifyToken': emailVerifyToken,
            ':site': site,
            ':isActive': 1
        }
    };
    return dynamodb.query(params, function onQuery(err, data) {
        return data;
    }).promise();
};


const findUserByRecoveryToken = (forgetPasswordToken,site) => {
    const params = {
        TableName : USERS_DB_NAME,
        IndexName: 'forget_password_recovery_token_global_index',
        KeyConditionExpression: 'forgetPasswordToken = :forgetPasswordToken and site = :site',
        FilterExpression: 'isActive = :isActive',
        ExpressionAttributeValues: {
            ':forgetPasswordToken': forgetPasswordToken,
            ':site': site,
            ':isActive': 1
        }
    };
    return dynamodb.query(params, function onQuery(err, data) {
        return data;
    }).promise();
};

module.exports = {
    saveUser,
    findUserByEmail,
    findUserByToken,
    updateUser,
    findUserByRecoveryToken
}

const saveFields = (fields) => {
    
}
