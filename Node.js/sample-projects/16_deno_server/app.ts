import { Application } from "https://deno.land/x/oak/mod.ts";

import todosRoutes from './routes/todo.routes.ts';

/**
 * Equivalent of 15_express_typescript, but using Deno instead of Node
 * 
 * It is started with :  deno run --allow-net ./app.ts
 */

const app = new Application();

app.use(todosRoutes.routes());
app.use(todosRoutes.allowedMethods());

await app.listen({ port: 3000 });