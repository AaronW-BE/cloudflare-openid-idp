import { Hono } from 'hono';
import { setupRoutes } from './routes.js';

const app = new Hono();

// Add a basic logger middleware
app.use('*', async (c, next) => {
  console.log(`[${c.req.method}] ${c.req.url}`);
  await next();
});

// Setup the OIDC routes
setupRoutes(app);

// Root endpoint just to show it's alive
app.get('/', (c) => c.text('Epic EAS OIDC Identity Provider is running.'));

export default app;
