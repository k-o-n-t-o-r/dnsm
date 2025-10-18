<script>
  import Router from 'svelte-spa-router';
  import Splash from './routes/Splash.svelte';
  import Inbox from './routes/Inbox.svelte';
  import BrowserTest from './routes/BrowserTest.svelte';

  const routes = {
    '/': Splash,
    '/inbox': Inbox,
    '/browser-test': BrowserTest,
  };
</script>

<Router {routes} />
