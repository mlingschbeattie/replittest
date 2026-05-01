import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { Layout } from "@/components/layout";

import Dashboard from "@/pages/dashboard";
import Scanner from "@/pages/scanner";
import Packets from "@/pages/packets";
import Logs from "@/pages/logs";
import Cve from "@/pages/cve";
import Hash from "@/pages/hash";
import Encode from "@/pages/encode";
import Password from "@/pages/password";

const queryClient = new QueryClient();

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/scanner" component={Scanner} />
        <Route path="/packets" component={Packets} />
        <Route path="/logs" component={Logs} />
        <Route path="/cve" component={Cve} />
        <Route path="/hash" component={Hash} />
        <Route path="/encode" component={Encode} />
        <Route path="/password" component={Password} />
        <Route component={NotFound} />
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
