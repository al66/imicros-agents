/**
 * @license MIT, imicros.de (c) 2020 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const { v4: uuid } = require("uuid");
const crypto = require("crypto");
const bcrypt 		= require("bcrypt");
const jwt 			= require("jsonwebtoken");
const { decode } = require("punycode");

/** Actions */
// create { label } => { serviceId }
// delete { serviceId } => true|false
// get { serviceId } => { serviceId, label, token[] }
// getAll { } => [ { serviceId, label, token[] } ]
// generateAuthToken { serviceId } => { tokenId, created, expire, authToken }
// getAuthToken { tokenId } => { tokenId, created, expire, authToken }
// removeAuthToken { tokenId } =>  true
// login { serviceId, authToken } => { serviceToken, accessToken }
// verify { serviceToken } => { serviceId }
// grantAccess { serviceId } => { result: true|false }
// requestAccess { ownerId } => { token }

module.exports = {
    name: "agents",
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
         * create agent
         * 
         * @actions
         * @param {String} label
         * 
         * @returns {Object} { serviceId }
         */
        create: {
            acl: "before",
            params: {
                label: { type: "string" },
                role: { type: "string", optional: true }
            },
            async handler({ params: { label, role = "." }, meta: { ownerId, ...otherMeta }}) {
                let serviceId = uuid();

                this.logger.info("agents.create", { label, role, ownerId, ...otherMeta });
                // retrieve grant token
                let grantToken;
                let opts = {
                    meta: {
                        ownerId,
                        service: {
                            serviceToken: this.signedJWT({ type: "service_token", serviceId, label, role, ownerId, temp: true }),
                            serviceId
                        },
                        ...otherMeta
                    }
                };
                try {
                    let res = await this.broker.call(this.services.acl + ".grantAccess", {}, opts);
                    if (res && res.token) grantToken = res.token;
                } catch (err) {
                    this.logger.error("Failed to retrieve grant token", { ownerId });
                }
                if (!grantToken) throw new Error("Failed to retrieve grant token");
                
                let queryParams = {
                    ownerId,
                    serviceId,
                    role,
                    label,
                    token: grantToken
                };
                let statement = "MERGE (a:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "SET a.label = {label}, a.role = {role}, a.token = {token} ";
                statement += "RETURN a.uid AS id;";
                this.logger.debug("create agent", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (result[0]) {
                    return { serviceId: result[0].id };
                }
                // failed
                this.logger.debug("failed to create agent");
                return null;
            }
        },        

        /**
         * delete agent
         * 
         * @actions
         * @param {String} serviceId
         * 
         * @returns {Boolean} result
         */
        delete: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" }
            },
            async handler({ params: { serviceId }, meta: { ownerId }}) {
                if (!ownerId) throw new Error("not authorized");

                let queryParams = {
                    ownerId,
                    serviceId
                };
                let statement = "MATCH (a:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "WITH a ";
                statement += "MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "DETACH DELETE t, a ";
                statement += ";";
                this.logger.debug("remove agent", { statement, queryParams });
                await this.run(statement, queryParams);                    
                return true;
                
            }
        },        

        /**
         * get agent
         * 
         * @actions
         * @param {String} serviceId
         * 
         * @returns {Object} Agent - { serviceId, label, token[] }
         */
        get: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" }
            },
            async handler({ params: { serviceId }, meta: { ownerId }}) {
                if (!ownerId) throw new Error("not authorized");

                let queryParams = {
                    ownerId,
                    serviceId
                };
                let statement = "MATCH (a:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "OPTIONAL MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "WITH a, COLLECT({ tokenId: t.uid, created: t.created, expire: t.expire }) AS token ";
                statement += "RETURN a.uid AS serviceId, a.label AS label, a.role AS role, token ";
                statement += ";";
                this.logger.debug("get agent", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (result[0]) {
                    let agent = result[0];
                    if (!agent.token) agent.token = [];
                    if (agent.token.length === 1 && agent.token[0].tokenId === null) agent.token = [];
                    return agent;
                }
                // failed
                this.logger.debug("failed to get agent");
                return null;
            }
        },        
        
        /**
         * get all agents
         * 
         * @actions
         * 
         * @returns {Array} agents[] - [{ serviceId, label, token[] }]
         */
        getAll: {
            acl: "before",
            async handler({ meta: { ownerId }}) {
                if (!ownerId) throw new Error("not authorized");

                let queryParams = {
                    ownerId
                };
                let statement = "MATCH (a:Agent { ownerId: {ownerId} }) ";
                statement += "OPTIONAL MATCH (t:Token)-[:ASSIGNED]->(a) ";
                statement += "WITH a, COLLECT({ tokenId: t.uid, created: t.created, expire: t.expire }) AS token ";
                statement += "RETURN a.uid AS serviceId, a.label AS label, a.role AS role, token ";
                statement += ";";
                /*
                let statement = "MATCH (a:Agent { ownerId: {ownerId} }) ";
                statement += "RETURN a.uid AS serviceId, a.label AS label, a.token AS token ";
                statement += ";";
                */
                this.logger.debug("get agents", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (result[0]) {
                    let agents = result.map(a => {
                        if (!a.token) a.token = [];
                        if (a.token.length === 1 && a.token[0].tokenId === null) a.token = [];
                        return a;
                    });
                    return agents;
                }
                // failed
                this.logger.debug("failed to get agents");
                return null;
            }
        },        
        
        /**
         * generate auth token for login
         * 
         * @actions
         * @param {String} serviceId
         * 
         * @returns {Object} authToken - { tokenId, created, expire, authToken }
         */
        generateAuthToken: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" },
                expire: { type: "number", optional: true }
            },
            async handler({ params: { serviceId, expire }, meta: { ownerId, ...moreMeta }, ...moreCtx}) {
                if (!ownerId) throw new Error("not authorized");

                let authToken = crypto.randomBytes(64).toString("hex");
                let token = {
                    tokenId: uuid(), 
                    created: Date.now(), 
                    expire: expire || 1000 * 60 * 60 * 24 * 365,   // default: 1 year
                    authToken
                };
                let raw = {
                    authToken: {
                        _encrypt: {
                            value: authToken
                        }
                    }
                };
                let encrypted = await this.encrypt({ ctx: { meta: { ownerId, ...moreMeta }, ...moreCtx }, object: raw });  
                let queryParams = {
                    ownerId,
                    serviceId,
                    tokenId: token.tokenId,
                    created: token.created,
                    expire: token.expire,
                    authToken: encrypted.authToken ? JSON.stringify(encrypted.authToken) : ".",
                    hashed: bcrypt.hashSync(authToken, 10)
                };
                
                // save token
                let statement = "MATCH (a:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "WITH a ";
                statement += "MERGE (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(a) ";
                statement += "SET t.created = {created}, t.expire = {expire}, t.authToken = {authToken}, t.hashed = {hashed} ";
                statement += "RETURN t.uid AS id ";
                await this.run(statement, queryParams);
                
                return token;
            }
        },        

        /**
         * get auth token details
         * 
         * @actions
         * @param {String} serviceId
         * @param {String} tokenId
         * 
         * @returns {Object} authToken - { tokenId, created, expire, authToken }
         */
        getAuthToken: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" },
                tokenId: { type: "uuid" }
            },
            async handler({ params: { serviceId, tokenId }, meta: { ownerId, ...moreMeta }, ...moreCtx}) {
                if (!ownerId) throw new Error("not authorized");

                let queryParams = {
                    ownerId,
                    tokenId,
                    serviceId
                };
                
                // get token
                let statement = "MATCH (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(a:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "RETURN t.uid AS tokenId, t.created AS created, t.expire AS expire, t.authToken AS authToken ;";
                let result = await this.run(statement, queryParams);
                if (result && result[0]) {
                    let token = result[0];
                    if (token.authToken && token.authToken !== "." ) token.authToken = JSON.parse(token.authToken);
                    if (token.authToken === ".") delete token.authToken;
                    token = await this.decrypt({ ctx: { meta: { ownerId, ...moreMeta }, ...moreCtx }, object: token });
                    return token;
                }
                return null;
            }
        },        

        /**
         * remove auth token
         * 
         * @actions
         * @param {String} serviceId
         * @param {String} tokenId
         * 
         * @returns {Boolean} result - true
         */
        removeAuthToken: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" },
                tokenId: { type: "uuid" }
            },
            async handler({ params: { serviceId, tokenId }, meta: { ownerId }}) {
                if (!ownerId) throw new Error("not authorized");

                let queryParams = {
                    ownerId,
                    tokenId,
                    serviceId
                };
                
                // get token
                let statement = "MATCH (t:Token { uid: {tokenId}, ownerId: {ownerId} })-[:ASSIGNED]->(:Agent { uid: {serviceId}, ownerId: {ownerId} }) ";
                statement += "DETACH DELETE t;";
                await this.run(statement, queryParams);
                return true;
            }
        },        
        
        /**
         * login
         * 
         * @actions
         * @param {String} serviceId
         * @param {String} authToken
         * 
         * @returns {Object} { sessionToken, accessToken }
         */
        login: {
            params: {
                serviceId: { type: "uuid" },
                authToken: { type: "string", min: 20 }
            },
            async handler({ params: { serviceId, authToken }}) {
                // find Agent
                let queryParams = {
                    serviceId
                };
                let statement = "MATCH (t:Token)-[:ASSIGNED]->(a:Agent { uid: {serviceId} }) ";
                statement += "RETURN t.created AS created, t.expire AS expire, t.hashed AS hashed, a.uid AS serviceId,  ";
                statement += "a.ownerId AS ownerId, a.role AS role, a.token AS token, a.label AS label;";
                this.logger.debug("get agent for login", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (Array.isArray(result)) {
                    for (let i = 0; i < result.length; i++) {
                        let check = await bcrypt.compare(authToken, result[i].hashed);
                        if (check) {
                            // if member, return service token and access token
                            if (result[i].role === "member" && result[i].token ) {
                                try {
                                    // exchange grant token against access token
                                    let serviceToken = this.signedJWT({ type: "service_token", serviceId });
                                    let opts = {
                                        meta: { service: { serviceToken }}
                                    };
                                    let { token } = await this.broker.call(`${this.services.acl}.exchangeToken`, { token: result[i].token }, opts);
                                    if (!token) throw new Error("failed to retrieve access token");
                                    return {
                                        serviceToken,
                                        accessToken: token
                                    };
                                } catch (err) {
                                    this.logger.error("Failed to retrieve access token", { serviceId });
                                }
                            // return service token only
                            } else {
                                return {
                                    serviceToken: this.signedJWT({ type: "service_token", serviceId })
                                };
                            }

                        }
                    }
                }
                // failed
                this.logger.debug("failed to login to Agent");
                throw new Error("unvalid Agent or unvalid password");

            }
        },        
        
        /**
         * verify service token
         * 
         * @actions
         * @param {String} serviceToken
         * 
         * @returns {Object} { serviceId }
         */
        verify: {
            visibility: "public",
            params: {
                serviceToken: { type: "string" }
            },
            async handler({ params: { serviceToken }}) {
                return new Promise((resolve, reject) => {
                    jwt.verify(serviceToken, this.jwtSecret, (err, decoded) => {
                        if (err)
                            return reject(new Error("token not valid", { serviceToken } ));

                        resolve(decoded);
                    });
                })
                    .then(decoded => {
                        if (decoded.type == "service_token" && decoded.serviceId) {
                        
                            if (decoded.temp) return [{ serviceId: decoded.serviceId, role: decoded.role, label: decoded.label, ownerId: decoded.ownerId }];

                            let queryParams = {
                                serviceId: decoded.serviceId
                            };
                            let statement = "MATCH (a:Agent { uid: {serviceId} }) ";
                            statement += "RETURN a.uid AS serviceId, a.role AS role, a.label AS label, a.ownerId AS ownerId ";
                            statement += ";";
                            this.logger.debug("get agent (verify)", { statement, queryParams });
                            return this.run(statement, queryParams);
                        }
                    })
                    .then(result => {
                        if (result[0]) {
                            return { service: result[0] };
                        }

                        // no valid agent    
                        throw new Error("token not valid", { serviceToken } );
                    })
                    .catch(err => {
                        this.logger.debug("failed to verify token", { serviceToken, err });
                        /* istanbul ignore next */  // Just to wrap any other possible error
                        throw new Error("token not valid", { serviceToken } );
                    });
            }
        },

        /**
         * garnt access for this service
         * 
         * @actions
         * @param {String} serviceId
         * 
         * @returns {Object} { result: true|false }
         */
        grantAccess: {
            acl: "before",
            params: {
                serviceId: { type: "uuid", optional: true }
            },
            async handler({ params, meta }) {
                let { acl: { ownerId }, service: { serviceToken } } = meta;
                if (!ownerId) throw new Error("not authorized");

                let { service: { serviceId = null }  } = serviceToken ? await this.actions.verify({ serviceToken }) : { service: { serviceId: params.serviceId }};
                if (!serviceId) throw new Error("unkwon service");

                let opts = {
                    meta
                };
                try {
                    let { token } = await this.broker.call(this.services.acl + ".grantAccess", { }, opts);
                    if (token) {
                        let queryParams = {
                            ownerId,
                            serviceId,
                            token
                        };
                        let statement = "MERGE (a:Agent { uid: {serviceId} })<-[r:GRANT]-(g:Group { uid: {ownerId}}) ";
                        statement += "SET r.grantToken = {token} ";
                        statement += ";";
                        this.logger.debug("add grant", { statement, queryParams });
                        await this.run(statement, queryParams);                    
                        return true;
                    }
                } catch (err) {
                    this.logger.error("Failed to retrieve & save grant token", { serviceId, err });
                    return false;
                }
                
            }
        },
        
        /**
         * garnt access for this service
         * 
         * @actions
         * @param {String} ownerId
         * 
         * @returns {Object} { token }
         */
        requestAccess: {
            params: {
                ownerId: { type: "string" }
            },
            async handler({ params: { ownerId }, meta: { service: { serviceToken }} }) {
                let { service: { serviceId = null } } = await this.actions.verify({ serviceToken });
                if (!serviceId) throw new Error("service not authorized");

                try {
                    // get stored grant token
                    let queryParams = {
                        ownerId,
                        serviceId
                    };
                    let statement = "MATCH (a:Agent { uid: {serviceId} })<-[r:GRANT]-(g:Group { uid: {ownerId}}) ";
                    statement += "RETURN r.grantToken AS token";
                    statement += ";";
                    this.logger.debug("get grant token", { statement, queryParams });
                    const [ { token: grantToken }] = await this.run(statement, queryParams);                    
                    if (!grantToken) throw new Error("service not granted");

                    // exchange against access token
                    let opts = {
                        meta: { service: { serviceToken }}
                    };
                    let { token } = await this.broker.call(`${this.services.acl}.exchangeToken`, { token: grantToken }, opts);
                    if (!token) throw new Error("failed to retrieve access token");
                    return { token };
                } catch (err) {
                    this.logger.error("Failed to retrieve access token", { serviceId, ownerId, err });
                    throw new Error("failed to retrieve access token");
                }
                
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
         * @return {String} Signed token
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
        
        const { services: { acl = "acl" } } = this.settings;
        this.services = { acl };
        // ES11 
        // this.services = {
        //     acl: this.settings?.services?.acl ?? "acl"
        // };

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