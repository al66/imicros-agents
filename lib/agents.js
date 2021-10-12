/**
 * @license MIT, imicros.de (c) 2020 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const { Serializer } = require("./util/serializer");
const { v4: uuid } = require("uuid");
const crypto = require("crypto");
const jwt 			= require("jsonwebtoken");

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
                if (role === "member") {
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
                }
                let queryParams = {
                    ownerId,
                    serviceId,
                    role,
                    label,
                    token: grantToken || false
                };
                let statement = "MERGE (a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
                statement += "SET a.label = $label, a.role = $role, a.token = $token ";
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
         * rename agent
         * 
         * @actions
         * @param {String} label
         * 
         * @returns {Object} { serviceId }
         */
        rename: {
            acl: "before",
            params: {
                serviceId: { type: "uuid" },
                label: { type: "string" }
            },
            async handler({ params: { serviceId, label }, meta: { ownerId }}) {
                let queryParams = {
                    ownerId,
                    serviceId,
                    label
                };
                let statement = "MATCH (a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
                statement += "SET a.label = $label ";
                statement += "RETURN a.uid AS serviceId, a.label AS label;";
                this.logger.debug("rename agent", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (result[0]) {
                    return result[0];
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
                let statement = "MATCH (a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
                statement += "OPTIONAL MATCH (t:Token)-[:ASSIGNED]->(a) ";
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
                let statement = "MATCH (a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
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
                let statement = "MATCH (a:Agent { ownerId: $ownerId }) ";
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
                } else if (Array.isArray(result)) {
                    return [];
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
                let encrypted = await this.encryptData({ meta: { ownerId, ...moreMeta }, ...moreCtx }, authToken); 
                let queryParams = {
                    ownerId,
                    serviceId,
                    tokenId: token.tokenId,
                    created: token.created,
                    expire: token.expire,
                    authToken: encrypted,
                    hashed: this.getHash(authToken)
                };
                
                // save token
                let statement = "MATCH (a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
                statement += "WITH a ";
                statement += "MERGE (t:Token { uid: $tokenId, ownerId: $ownerId })-[:ASSIGNED]->(a) ";
                statement += "SET t.created = $created, t.expire = $expire, t.authToken = $authToken, t.hashed = $hashed ";
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
                let statement = "MATCH (t:Token { uid: $tokenId, ownerId: $ownerId })-[:ASSIGNED]->(a:Agent { uid: $serviceId, ownerId: $ownerId }) ";
                statement += "RETURN t.uid AS tokenId, t.created AS created, t.expire AS expire, t.authToken AS authToken ;";
                let result = await this.run(statement, queryParams);
                if (result && result[0]) {
                    let token = result[0];
                    if (token.authToken === ".") delete token.authToken;
                    if (token.authToken) token.authToken = await this.decryptData({ meta: { ownerId, ...moreMeta }, ...moreCtx }, token.authToken );
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
                let statement = "MATCH (t:Token { uid: $tokenId, ownerId: $ownerId })-[:ASSIGNED]->(:Agent { uid: $serviceId, ownerId: $ownerId }) ";
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
                let statement = "MATCH (t:Token)-[:ASSIGNED]->(a:Agent { uid: $serviceId }) ";
                statement += "RETURN t.created AS created, t.expire AS expire, t.hashed AS hashed, a.uid AS serviceId,  ";
                statement += "a.ownerId AS ownerId, a.role AS role, a.token AS token, a.label AS label;";
                this.logger.debug("get agent for login", { statement, queryParams });
                let result = await this.run(statement, queryParams);
                if (Array.isArray(result)) {
                    for (let i = 0; i < result.length; i++) {
                        let check = ( result[i].hashed === this.getHash(authToken) );
                        if (check) {
                            // if member, return service token and access token
                            if (result[i].role === "member" && result[i].token ) {
                                try {
                                    // exchange grant token against access token
                                    let serviceToken = this.signedJWT({ type: "service_token", serviceId });
                                    let opts = {
                                        meta: { service: { serviceToken }}
                                    };
                                    let { token } = await this.broker.call(`${this.services.acl}.exchangeToken`, { token: result[i].token, expiresIn: this.expiresIn }, opts);
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
                            let statement = "MATCH (a:Agent { uid: $serviceId }) ";
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
                        let statement = "MERGE (a:Agent { uid: $serviceId })<-[r:GRANT]-(g:Group { uid: $ownerId}) ";
                        statement += "SET r.grantToken = $token ";
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
                    let statement = "MATCH (a:Agent { uid: $serviceId })<-[r:GRANT]-(g:Group { uid: $ownerId }) ";
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

        getHash(value) {
            return crypto.createHash("sha256")
                .update(value)
                .digest("hex");
        },

        async encryptData(ctx, obj) {
            // serialize and encrypt user data 
            let oek = await this.getKey({ ctx });
            let iv = crypto.randomBytes(this.encryption.ivlen);
            let serialized = await this.serializer.serialize(obj); 
            // this.logger.debug("Serialized data to encrypt", serialized);
            try {
                // hash encription key with iv
                let key = crypto.pbkdf2Sync(oek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                // encrypt value
                let value = this.encrypt({ value: serialized, secret: key, iv });
                // this.logger.info("Has been encrypted", { value });
                // let decryptedAgain = this.decrypt({ encrypted: value, secret: key, iv });
                // this.logger.info("Has been encrypted", { decryptedAgain });
                let encrypted = await this.serializer.serialize({
                    key: oek.id,
                    iv: iv.toString("hex"),
                    value    
                });
                return encrypted;
            } catch (err) {
                this.logger.error("Failed to encrypt value", { 
                    error: err, 
                    iterations: this.encryption.iterations, 
                    keylen: this.encryption.keylen,
                    digest: this.encryption.digest
                });
                throw new Error("failed to encrypt");
            }
        },

        async decryptData(ctx, data) {
            if (!data || !(data.length > 0)) return {};
            try {
                let container = await this.serializer.deserialize(data);
                // this.logger.info("container to decrypt", container);
                let iv = Buffer.from(container.iv, "hex");
                let encrypted = container.value;
                let oek = await this.getKey({ ctx, id: container.key });
                // hash received key with salt
                let key = crypto.pbkdf2Sync(oek.key, iv, this.encryption.iterations, this.encryption.keylen, this.encryption.digest);
                let value = this.decrypt({ encrypted, secret: key, iv });
                // deserialize value
                value = await this.serializer.deserialize(value);
                // this.logger.debug("decrypted data", value);
                return value;            
            } catch (err) {
                this.logger.error("failed to decrypt", err);
                throw new Error("failed to decrypt");
            }
        },

        async getKey ({ ctx = null, id = null } = {}) {
            
            let result = {};
            
            // try to retrieve from keys service
            let opts;
            if ( ctx ) opts = { meta: ctx.meta };
            let params = { 
                service: this.name
            };
            if ( id ) params.id = id;
            
            // call key service and retrieve keys
            try {
                result = await this.broker.call(this.services.keys + ".getOek", params, opts);
                this.logger.debug("Got key from key service", { id: id });
            } catch (err) {
                this.logger.error("Failed to receive key from key service", { params: params, meta: ctx.meta });
                throw err;
            }
            if (!result.id || !result.key) throw new Error("Failed to receive key from service", { result: result });
            return result;
        },

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
        },
        
        encrypt ({ value = ".", secret, iv }) {
            let cipher = crypto.createCipheriv("aes-256-cbc", secret, iv);
            let encrypted = cipher.update(value, "utf8", "hex");
            encrypted += cipher.final("hex");
            return encrypted;
        },

        decrypt ({ encrypted, secret, iv }) {
            let decipher = crypto.createDecipheriv("aes-256-cbc", secret, iv);
            let decrypted = decipher.update(encrypted, "hex", "utf8");
            decrypted += decipher.final("utf8");
            return decrypted;            
        }
        
    },
    
    /**
     * Service created lifecycle event handler
     */
    created() {
        
        this.jwtSecret = process.env.AGENTS_JWT_SECRET;
        if (!this.jwtSecret) throw new Error("Missing jwt secret - service can't be started");
        
        this.expiresIn = 60 * 60 * 24;

        // instance of serializer
        this.serializer = new Serializer();

        // encryption setup
        this.encryption = {
            iterations: 1000,
            ivlen: 16,
            keylen: 32,
            digest: "sha512"
        };

        // set actions
        this.services = {
            keys: this.settings?.services?.keys ?? "keys",
            acl: this.settings?.services?.acl ?? "acl"
        };        

        // service token to retrieve encryption key from keys service
        this.serviceToken = process.env.SERVICE_TOKEN;

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