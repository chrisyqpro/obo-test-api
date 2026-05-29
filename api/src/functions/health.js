const { app } = require("@azure/functions");

app.http("health", {
  methods: ["GET"],
  authLevel: "anonymous",
  handler: async () => {
    return {
      status: 200,
      jsonBody: {
        status: "ok",
        service: "swa-obo-token-api"
      }
    };
  }
});