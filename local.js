process.env.NEO4J_URI = "bolt://192.168.2.124:30008";    //7687
process.env.NEO4J_USER = "neo4j";
process.env.NEO4J_PASSWORD = "neo4j";
process.env.AGENTS_JWT_SECRET = "my JWT secret";

module.exports =  {
    "collectCoverageFrom": [
        "lib/*.js",
        "lib/util/*.js",
        "!node_modules/",
        "!/dev/",
        "!test/helper/*.js"
    ],
    "testPathIgnorePatterns": [
        "/node_modules/",
        "/dev/"
    ],
    "rootDir": ".",
    "roots": [
        "./test"
    ]
};