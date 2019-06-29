/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

const dbMixin       = require("./db.neo4j");
const uuidv4 = require("uuid/v4");
const { AclMixin } = require("imicros-acl");

/** Actions */
// action create { label } => { id (account), label, ownerId }

module.exports = {
    name: "accounts",
    mixins: [dbMixin, AclMixin],
    
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
         * Create a new account
         * 
         * @actions
         * @param {String} name
         * 
         * @returns {Object} Created account with id
         */
        create: {
            params: {
                label: "string"
            },
            handler(ctx) {
                let ownerId = this.getOwnerId({ ctx: ctx, abort: true });
                
                let params = {
                    accountId: uuidv4(),
                    label: ctx.params.label,
                    ownerId: ownerId
                };
                let statement = "CREATE (a:Account { uid: {accountId}, label: {label} })";
                statement += "MERGE (o:Owner { uid: {ownerId} }) ";
                statement += "MERGE (u)-[r:OWNER]->(a)";
                statement += "RETURN a.uid AS id, a.label AS label, o.uid AS ownerId;";
                return this.run(statement, params);
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
         * Check User
         * 
         * @param {Object} meta data of call 
         * 
         * @returns {Object} user entity
         */
        isAuthenticated (meta) {
            // Prepared enhancement: individual maps via settings 
            // from : to
            let map = {
                "user.id": "id",        // from meta.user.id to user.id
                "user.email": "email"   // from meta.user.email to user.email
            };
            if (!user || !user.id || !user.email ) {
                throw new GroupsNotAuthenticated("not authenticated" );
            }
            return user;
        }
        
    },

    /**
     * Service created lifecycle event handler
     */
    created() {},

    /**
     * Service started lifecycle event handler
     */
    started() {},

    /**
     * Service stopped lifecycle event handler
     */
    stopped() {}
    
};