const { v4: uuid } = require("uuid");

// mock keys service
const Keys = {
    name: "keys",
    actions: {
        getOek: {
            params: {
                service: { type: "string" },
                id: { type: "string", optional: true }
            },
            handler(ctx) {
                ctx.broker.logger.info("getOek", { params: ctx.params });
                if (!ctx.params || !ctx.params.service) throw new Error("Missing service name");
                if ( ctx.params.id == "prev" ) {
                    return {
                        id: this.prev,
                        key: "myPreviousSecret"
                    };    
                }
                return {
                    id: this.current,
                    key: "mySecret"
                };
            }
        }
    },
    created() {
        this.prev = uuid();
        this.current = uuid();
        this.broker.logger.info("keys", { current: this.current, previous: this.prev });
    } 
};

module.exports = {
    Keys
};

