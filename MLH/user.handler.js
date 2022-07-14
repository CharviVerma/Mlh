const dynamoDbUser = require('../dynamo/user.persistance')
const helpers = require('../util/helper');
const bcrypt = require('bcryptjs');
const emailService = require('../services/email.service')
const createResponse = helpers.createResponse;
const saltRounds = 10;
const specialCharacters = ['!', '#', '$', '%', '&', "'", '*', '/', '\\', '=', '?', '^', '`', '{', '}', '|', '[', ']', '"', '(', ')', ',', ':', ';', '<', '>'];
const uuidv4 = require('uuid/v4');

module.exports.createUser = async (event, context) => {
    const {name, country, email, password, site} = JSON.parse(event.body);

    if (email) {
        specialCharacters.forEach(specialCharater => {
            if (email.includes(specialCharater)) {
                return context.succeed(createResponse(401, {
                    'error': `Special character ${specialCharater} is not allowed in email.`,
                    'code': 'SPECIAL_CHARACTER_NOT_ALLOWED',
                }, context.domain));
            }
        });

        let data;
        if (email) {
            data = await dynamoDbUser.findUserByEmail(email, site);
        }
        if (data && data.Count > 0) {
            return context.succeed(createResponse(400, {
                'code': 'EMAIL_ALREADY_LINKED',
                'error': 'This email address is already linked to an existing account. Please login using the account.'
            }, context.domain));
        }

        const emailVerifyToken = uuidv4();
        const profile = {
            name: name,
            country: country,
            email: email,
            password: bcrypt.hashSync(password, saltRounds),
            site: site,
            emailVerifyToken: emailVerifyToken,
            isEmailVerified: false
        }

        await dynamoDbUser.saveUser(profile);

        await emailService.sendMail('Please Verify Your Email Address.', 'Thank you for registering! Please verify your email by clicking on this link. http://localhost:2100/email/verify?token=' + emailVerifyToken, email)

        return context.succeed(createResponse(200, {
            'code': 'SUCCESS',
            'msg': 'User Successfully Registered.'
        }, context.domain));

    }
}

module.exports.verifyToken = async (event, context) => {
    const token = event.pathParameters.token;
    const siteId = event.multiValueHeaders['siteId'][0];
    console.log(siteId);
    if (!token) {
        return context.succeed(createResponse(400, {
            'code': 'TOKEN_NOT_FOUND',
            'error': 'Bad Request Please Send Token along with this request.'
        }, context.domain));
    }

    const userItem = await dynamoDbUser.findUserByToken(token, siteId);
    if (!userItem.Items[0]) {
        return context.succeed(createResponse(400, {
            'code': 'INVALID_TOKEN',
            'error': 'Your Token is used or expired, please re-generate.'
        }, context.domain));
    }

    const user = userItem.Items[0];

    if (user.isEmailVerified) {
        return context.succeed(createResponse(200, {
            'code': 'TOKEN_ALREADY_VERIFIED',
            'error': 'Your Email Already Verified.'
        }, context.domain));
    }

    user.isEmailVerified = true;
    user.emailVerifyToken = 'null';

    await dynamoDbUser.updateUser(user);
    await emailService.sendMail('Welcome to Bjobz.', 'Thank you for registering! Please verify your email by clicking on this link. http://localhost:2100/email/verify?token=', user.email);

    return context.succeed(createResponse(200, {
        'code': 'TOKEN_VERIFIED',
        'error': 'Email Verification successfully completed..'
    }, context.domain));

}

module.exports.forgetPassword = async (event, context) => {
    const {email, site} = JSON.parse(event.body);

    if (!email || email === '') {
        return context.succeed(createResponse(401, {
            'code': 'EMAIL_NOT_FOUND',
            'error': 'Please provide your registered email.'
        }, context.domain));
    }


    if (email) {
        specialCharacters.forEach(specialCharater => {
            if (email.includes(specialCharater)) {
                return context.succeed(createResponse(401, {
                    'error': `Special character ${specialCharater} is not allowed in email.`,
                    'code': 'SPECIAL_CHARACTER_NOT_ALLOWED',
                }, context.domain));
            }
        });
    }
    const data = await dynamoDbUser.findUserByEmail(email, site);
    if (data && data.Count <= 0) {
        return context.succeed(createResponse(400, {
            'code': 'USER_NOT_FOUND',
            'error': 'Your Email is not registered with us, please register your self.'
        }, context.domain));
    }

    const user = data.Items[0];
    const forgetPasswordToken = uuidv4();

    user.forgetPasswordToken = forgetPasswordToken;
    await dynamoDbUser.updateUser(user);

    await emailService.sendMail('Please Verify Your Email Address.', 'Thank you for registering! Please verify your email by clicking on this link. http://localhost:2100/forget/password/recover?token=' + forgetPasswordToken, email)

    return context.succeed(createResponse(200, {
        'code': 'FORGET_PASSWORD_RECOVER_MAIL_SENT',
        'error': 'Forget password mail sent to given email, please open that email and click on the link.'
    }, context.domain));
}

module.exports.forgetPasswordRecovery = async (event, context) => {
    const token = event.queryStringParameters.token;
    const siteId = event.multiValueHeaders['siteId'][0];

    if (!token) {
        return context.succeed(createResponse(400, {
            'code': 'TOKEN_NOT_FOUND',
            'error': 'Bad Request Please Send Token along with this request.'
        }, context.domain));
    }

    const userItem = await dynamoDbUser.findUserByRecoveryToken(token, siteId);
    if (!userItem.Items[0]) {
        return context.succeed(createResponse(400, {
            'code': 'INVALID_TOKEN',
            'error': 'Your Token is used or expired, please re-generate.'
        }, context.domain));
    }

    const user = userItem.Items[0];
    return context.succeed(createResponse(200, {"data": {"name": user.name, "token": token}}, context.domain));

}


module.exports.recoveryToken = async (event, context) => {
    const token = event.queryStringParameters.token;
    const siteId = event.multiValueHeaders['siteId'][0];

    if (!token) {
        return context.succeed(createResponse(400, {
            'code': 'TOKEN_NOT_FOUND',
            'error': 'Bad Request Please Send Token along with this request.'
        }, context.domain));
    }

    const userItem = await dynamoDbUser.findUserByRecoveryToken(token, siteId);
    if (!userItem.Items[0]) {
        return context.succeed(createResponse(400, {
            'code': 'INVALID_TOKEN',
            'error': 'Your Token is used or expired, please re-generate.'
        }, context.domain));
    }

    const user = userItem.Items[0];
    return context.succeed(createResponse(200, {"data": {"name": user.name, "token": token, "changedPassword": newpass, "confirmedPassword": confirm}}, context.domain));
}
