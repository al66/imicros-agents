/**
 * @license MIT, imicros.de (c) 2020 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const _ = require("./util/lodash");
const { v4: uuid } = require("uuid");
const crypto = require("crypto");
const bcrypt 		= require("bcrypt");
const jwt 			= require("jsonwebtoken");

/** Actions */
// create { label } => { accountId }
// delete { accountId } => true|false
// get { accountId } => { accountId, label, token[] }
// getAll { } => [ { accountId, label, token[] } ]
// generateAuthToken { accountId } => { tokenId, created, expire, authToken }
// getAuthToken { tokenId } => { tokenId, created, expire, authToken }
// removeAuthToken { tokenId } =>  true
// login { accountId, authToken } => { sessionToken, accessToken }
// verify { sessionToken } => { accountId }

module.exports = {
    name: "account",
    mixins: [dbMixin],
    
    /**
     * Service settings
     */
    settings: {},
    
    /**
     * Service metadata
     */
    metadata: {},

    /**
     * Service dependencies
     */
    //dependencies: [],	

    /**
     * Actions
     */
    actions: {

        /**
         * create account
         * 
         * @actions
         * @param {String} label
         * 
         * @returns {Object} { accountId }
         */
        create: {
            acl: "before",
            params: {
                label: { type: "string" }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");
                
                let accountId = uuid();
                let params = {
                    ownerId,
                    accountId,
                    label: ctx.params.label
                };
                let statement = "MERGE (a:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "SET a.label = {label} ";
                statement += "RETURN a.uid AS id;";
                this.logger.debug("create account", { statement, params });
                let result = await this.run(statement, params);
                if (result[0]) {
                    return { accountId: result[0].id };
                }
                // failed
                this.logger.debug("failed to create account");
                return null;
            }
        },        

        /**
         * delete account
         * 
         * @actions
         * @param {String} accountId
         * 
         * @returns {Boolean} result
         */
        delete: {
            acl: "before",
            params: {
                accountId: { type: "uuid" }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let params = {
                    ownerId,
                    accountId: ctx.params.accountId
                };
                let statement = "MATCH (a:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "WITH a ";
                statement += "MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "DETACH DELETE t, a ";
                statement += ";";
                this.logger.debug("remove account", { statement, params });
                await this.run(statement, params);                    
                return true;
                
            }
        },        

        /**
         * get account
         * 
         * @actions
         * @param {String} accountId
         * 
         * @returns {Object} account - { accountId, label, token[] }
         */
        get: {
            acl: "before",
            params: {
                accountId: { type: "uuid" }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let params = {
                    ownerId,
                    accountId: ctx.params.accountId
                };
                let statement = "MATCH (a:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "OPTIONAL MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "WITH a, COLLECT({ tokenId: t.uid, created: t.created, expire: t.expire }) AS token ";
                statement += "RETURN a.uid AS accountId, a.label AS label, token ";
                statement += ";";
                this.logger.debug("get account", { statement, params });
                let result = await this.run(statement, params);
                if (result[0]) {
                    let account = result[0];
                    if (!account.token) account.token = [];
                    if (account.token.length === 1 && account.token[0].tokenId === null) account.token = [];
                    return account;
                }
                // failed
                this.logger.debug("failed to get account");
                return null;
            }
        },        
        
        /**
         * get all accounts
         * 
         * @actions
         * 
         * @returns {Array} accounts[] - [{ accountId, label, token[] }]
         */
        getAll: {
            acl: "before",
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let params = {
                    ownerId
                };
                let statement = "MATCH (a:Account { ownerId: {ownerId} }) ";
                statement += "OPTIONAL MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "WITH a, COLLECT({ tokenId: t.uid, created: t.created, expire: t.expire }) AS token ";
                statement += "RETURN a.uid AS accountId, a.label AS label, token ";
                statement += ";";
                /*
                let statement = "MATCH (a:Account { ownerId: {ownerId} }) ";
                statement += "RETURN a.uid AS accountId, a.label AS label, a.token AS token ";
                statement += ";";
                */
                this.logger.debug("get accounts", { statement, params });
                let result = await this.run(statement, params);
                if (result[0]) {
                    let accounts = result.map(a => {
                        if (!a.token) a.token = [];
                        if (a.token.length === 1 && a.token[0].tokenId === null) a.token = [];
                        return a;
                    });
                    return accounts;
                }
                // failed
                this.logger.debug("failed to get accounts");
                return null;
            }
        },        
        
        /**
         * generate auth token for login
         * 
         * @actions
         * @param {String} accountId
         * 
         * @returns {Object} authToken - { tokenId, created, expire, authToken }
         */
        generateAuthToken: {
            acl: "before",
            params: {
                accountId: { type: "uuid" },
                expire: { type: "number", optional: true }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let authToken = crypto.randomBytes(64).toString("hex");
                let token = {
                    tokenId: uuid(), 
                    created: Date.now(), 
                    expire: ctx.params.expire || 1000 * 60 * 60 * 24 * 365,   // default: 1 year
                    authToken
                };
                let raw = {
                    authToken: {
                        _encrypt: {
                            value: authToken
                        }
                    }
                };
                let encrypted = await this.encrypt({ ctx: ctx, object: raw });  
                let params = {
                    ownerId,
                    accountId: ctx.params.accountId,
                    tokenId: token.tokenId,
                    created: token.created,
                    expire: token.expire,
                    authToken: encrypted.authToken ? JSON.stringify(encrypted.authToken) : ".",
                    hashed: bcrypt.hashSync(authToken, 10)
                };
                
                // save token
                let statement = "MATCH (a:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "WITH a ";
                statement += "MERGE (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(a) ";
                statement += "SET t.created = {created}, t.expire = {expire}, t.authToken = {authToken}, t.hashed = {hashed} ";
                statement += "RETURN t.uid AS id ";
                await this.run(statement, params);
                
                return token;
            }
        },        

        /**
         * get auth token details
         * 
         * @actions
         * @param {String} accountId
         * @param {String} tokenId
         * 
         * @returns {Object} authToken - { tokenId, created, expire, authToken }
         */
        getAuthToken: {
            acl: "before",
            params: {
                accountId: { type: "uuid" },
                tokenId: { type: "uuid" }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let params = {
                    ownerId,
                    tokenId: ctx.params.tokenId,
                    accountId: ctx.params.accountId
                };
                
                // get token
                let statement = "MATCH (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(a:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "RETURN t.uid AS tokenId, t.created AS created, t.expire AS expire, t.authToken AS authToken ;";
                let result = await this.run(statement, params);
                if (result && result[0]) {
                    let token = result[0];
                    if (token.authToken && token.authToken !== "." ) token.authToken = JSON.parse(token.authToken);
                    if (token.authToken === ".") delete token.authToken;
                    token = await this.decrypt({ ctx: ctx, object: token });
                    return token;
                }
                return null;
            }
        },        

        /**
         * remove auth token
         * 
         * @actions
         * @param {String} accountId
         * @param {String} tokenId
         * 
         * @returns {Boolean} result - true
         */
        removeAuthToken: {
            acl: "before",
            params: {
                tokenId: { type: "uuid" }
            },
            async handler(ctx) {
                let ownerId = _.get(ctx,"meta.ownerId",null);
                if (!ownerId) throw new Error("not authorized");

                let params = {
                    ownerId,
                    tokenId: ctx.params.tokenId,
                    accountId: ctx.params.accountId
                };
                
                // get token
                let statement = "MATCH (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(:Account { uid: {accountId}, ownerId: {ownerId} }) ";
                statement += "DETACH DELETE t;";
                await this.run(statement, params);
                return true;
            }
        },        
        
        /**
         * login
         * 
         * @actions
         * @param {String} accountId
         * @param {String} authToken
         * 
         * @returns {Object} { sessionToken, accessToken }
         */
        login: {
            params: {
                accountId: { type: "uuid" },
                authToken: { type: "string", min: 20 }
            },
            async handler(ctx) {
                // find account
                let params = {
                    accountId: ctx.params.accountId
                };
                let statement = "MATCH (t:Token)-[:ASSIGNED]->(a:Account { uid: {accountId} }) ";
                statement += "RETURN t.created AS created, t.expire AS expire, t.hashed AS hashed, a.uid AS accountId,  ";
                statement += "a.ownerId AS ownerId, a.label AS label;";
                this.logger.debug("get account for login", { statement, params });
                let result = await this.run(statement, params);
                if (Array.isArray(result)) {
                    for (let i = 0; i < result.length; i++) {
                        let check = await bcrypt.compare(ctx.params.authToken, result[i].hashed);
                        if (check) {

                            let opts = {
                                meta: {
                                    serviceToken: this.serviceToken,
                                    accountId: ctx.params.accountId
                                }
                            };
                            try {
                                let res = await this.broker.call(this.services.acl + ".requestAccess", { forGroupId: result[i].ownerId }, opts);
                                if (res && res.token) {
                                    return {
                                        sessionToken: this.signedJWT({ type: "session_token", id: ctx.params.accountId }),
                                        accessToken: res.token
                                    };
                                }
                            } catch (err) {
                                this.logger.error("Failed to retrieve access token", { accountId: ctx.params.accountId });
                            }

                        }
                    }
                }
                // failed
                this.logger.debug("failed to login to account");
                throw new Error("unvalid account or unvalid password");

            }
        },        
        
        /**
         * verify session token
         * 
         * @actions
         * @param {String} sessionToken
         * 
         * @returns {Object} { accountId }
         */
        verify: {
            visibility: "public",
            params: {
                sessionToken: { type: "string" }
            },
            async handler(ctx) {
                return new Promise((resolve, reject) => {
                    jwt.verify(ctx.params.sessionToken, this.jwtSecret, (err, decoded) => {
                        if (err)
                            return reject(new Error("token not valid", { token: ctx.params.sessionToken } ));

                        resolve(decoded);
                    });
                })
                .then(decoded => {
                    if (decoded.type == "session_token" && decoded.id) {
                        
                        let params = {
                            accountId: decoded.id
                        };
                        let statement = "MATCH (a:Account { uid: {accountId} }) ";
                        statement += "RETURN a.uid AS accountId, a.label AS label, a.ownerId AS ownerId ";
                        statement += ";";
                        this.logger.debug("get account (verify)", { statement, params });
                        return this.run(statement, params);
                    }
                })
                .then(result => {
                    if (result[0]) {
                        return result[0];
                    }

                    // no valid account    
                    throw new Error("token not valid", { token: ctx.params.sessionToken } );
                })
                .catch(err => {
                    this.logger.debug("failed to verify token", { token: ctx.params.sessionToken, err });
                    /* istanbul ignore next */  // Just to wrap any other possible error
                    throw new Error("token not valid", { token: ctx.params.sessionToken } );
                });
            }
        }
        
    },
    
    /**
     * Events
     */
    events: {},

    /**
     * Methods
     */
    methods: {

        /**
         * Generate a signed JWT token
         * 
         * @param {Object} payload 
         * 
         * @returns {String} Signed token
         */
        signedJWT(payload) {
            let today = new Date();
            let exp = new Date(today);
            exp.setDate(today.getDate() + 60);
            payload.exp = Math.floor(exp.getTime() / 1000);

            return jwt.sign(payload, this.jwtSecret);
        }
        
        
    },
    
    /**
     * Service created lifecycle event handler
     */
    created() {
        
        this.jwtSecret = process.env.JWT_SECRET;
        if (!this.jwtSecret) throw new Error("Missing jwt secret - service can't be started");

        
        this.serviceToken = process.env.SERVICE_TOKEN;
        if (!this.serviceToken) throw new Error("Missing service token - service can't be started");
        
        this.services = {
            acl: _.get(this.settings,"services.acl","acl")
        };

        this.broker.waitForServices(Object.values(this.services));
        
    },

    /**
     * Service started lifecycle event handler
     */
    started() {},

    /**
     * Service stopped lifecycle event handler
     */
    stopped() {}
    
};