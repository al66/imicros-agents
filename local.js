process.env.URI = "bolt://192.168.2.124:7687";
process.env.JWT_SECRET = "my JWT secret";

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