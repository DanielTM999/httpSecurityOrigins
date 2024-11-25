# HttpSecurityConfigurar

## Descrição

O `HttpSecurityConfigurar` é um framework complementar ao [Origins](https://github.com/DanielTM999/origins), projetado para fornecer configurações de segurança HTTP de forma simples e eficiente. Ele permite configurar políticas de sessão, padrões de requisição, filtros de segurança e correspondências de requisição para autenticação e autorização.

## Instalação

1. Certifique-se de ter o framework [Origins](https://github.com/DanielTM999/origins) instalado e configurado.
2. Clone ou faça o download deste repositório.
3. Inclua o autoload do Composer no seu projeto:

# Uso

## Configuração Inicial

Crie uma classe que estenda `OnInit` para configurar as dependências iniciais:

```php
    use Daniel\Origins\DependencyManager;
    use Daniel\Origins\HttpMethod;
    use Daniel\Origins\Inject;
    use Daniel\Origins\OnInit;

    class HttpSecurity extends OnInit {
        
        #[Inject]
        private HttpSecurityConfigurar $httpManager;

        #[Inject]
        private FilterChain $httpfilter;

        #[Override]
        public function ConfigOnInit() : void {
            $this->httpManager->sessionPolice(SessionPolice::STATELESS)
                ->RequestPatterns(function(RequestMatcherAction $e) {
                    $e->Request("/")->authenticate(["adm"]);
                    $e->Request("/teste")->authenticate();
                    $e->Request("/teste2", HttpMethod::DELETE, "env_teste")->authenticate(["adm"]);
                })
                ->AddFilterBefore($this->httpfilter)
                //->AddFilterBefore(new FilterChain()) --> não irá ter ajuda do injetor de dependecias do Origin(injeção manul nesse caso);
                ->any()->permitAll();
        }
    }

    #[Dependency]
        class FilterChain extends SecurityFilterChain{
            
            public function filterPerRequest(Request $req){
                SecurityContext::setContext(new UserDatails());
            }
        }

        class UserDatails implements AuthContext{
            public function getUser():string{
                return "";
            }
            public function getPassword():string{
                return "";
            }
            public function getRoles():array{
                return ["adm"];
            }
        }
```

## Contribuição

Sinta-se à vontade para abrir issues e enviar pull requests. Toda contribuição é bem-vinda!
