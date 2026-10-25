import { app } from "./server.js";
const PORT = parseInt(process.env.PORT ?? "3200");
app.listen(PORT, () => console.log(`[verifier] on :${PORT}`));
