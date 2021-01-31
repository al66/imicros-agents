const { v4: uuid } = require("uuid");

class User {
    constructor () {
        let timestamp = Date.now();
        return {
            id: `1-${timestamp}` , 
            email: `1-${timestamp}@host.com`
        };
    }
}

const Token = {
    accessToken: "this is the access token",
    grantToken: "this is the grant token"
};
const user = new User();
const ownerId = uuid();
const meta = {
    ownerId: ownerId,
    acl: {
        accessToken: Token.accessToken,
        ownerId: ownerId
    }, 
    user: user
}; 

// mock acl middelware
const ACLMiddleware = {
    localAction(next, action) {
        return async function(ctx) {
            ctx.broker.logger.info("acl.middleware called", { meta: ctx.meta } );
            if (ctx.meta && ctx.meta.acl && ctx.meta.acl.accessToken === Token.accessToken) {
                ctx.meta.ownerId = ownerId;
                ctx.meta.acl = meta.acl;
            } else {
                delete ctx.meta.ownerId;
                ctx.meta.acl = {};
            }
            if (ctx.meta && ctx.meta.service && !ctx.meta.service.serviceToken) {
                ctx.meta.service = {};
            }
            ctx.broker.logger.info("ACL meta data has been set", { meta: ctx.meta, action: action.name });
            return next(ctx);
        };
    }    
};

// mock service acl
const ACL = {
    // name: "v1.acl",
    name: "acl",
    actions: {
        grantAccess: {
            async handler({ meta: { acl: { ownerId = null }, service: { serviceToken = null }}}) {
                this.logger.info("acl.grantAccess called", { ownerId, serviceToken } );
                let result = await this.broker.call("agents.verify", { serviceToken });
                this.logger.info("result agents.verify", { result });
                if (ownerId === meta.ownerId && serviceToken) {
                    this.logger.info("acl.grantAccess returned", { token: Token.grantToken } );
                    return { token: Token.grantToken }; 
                }
                return false;
            }
        },
        exchangeToken: {
            params: {
                token: { type: "string" }
            },
            async handler({ params: { token }, meta: { service: { serviceToken }}}) {
                this.logger.info("acl.exchangeToken called", { token, serviceToken } );
                if (serviceToken ) {
                    this.logger.info("acl.exchangeToken returned", { token: Token.accessToken } );
                    return { token: Token.accessToken }; 
                }
                return false;
            },
        }
    }
};

module.exports = {
    user,
    ownerId,
    meta,
    accessToken: Token.accessToken,
    ACL,
    ACLMiddleware
};
