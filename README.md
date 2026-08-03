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
            $this->httpManager->addEnvaroment(true, "seuAmbiente", function($httpManager){
                $httpManager->sessionPolice(SessionPolice::STATELESS)
                    ->RequestPatterns(function(RequestMatcherAction $e) {
                        $e->Request("/")->authenticate(["adm"]);
                        $e->Request("/teste")->authenticate();
                        $e->Request("/teste2", HttpMethod::DELETE)->authenticate(["adm"]);
                    })
                    ->AddFilterBefore($this->httpfilter)
                    //->AddFilterBefore(new FilterChain()) --> não irá ter ajuda do injetor de dependecias do Origin(injeção manul nesse caso);
                    ->any()->permitAll();
            });

            $this->httpManager->addEnvaroment(true, "seuOutroSeNescessarioAmbiente", function($httpManager){
                $httpManager->sessionPolice(SessionPolice::STATELESS)
                    ->RequestPatterns(function(RequestMatcherAction $e) {
                        $e->Request("/")->authenticate(["adm"]);
                        $e->Request("/teste")->authenticate();
                        $e->Request("/teste2", HttpMethod::DELETE)->authenticate(["adm"]);
                    })
                    ->AddFilterBefore($this->httpfilter)
                    //->AddFilterBefore(new FilterChain()) --> não irá ter ajuda do injetor de dependecias do Origin(injeção manul nesse caso);
                    ->any()->permitAll();
            });

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

## Validator de autorização customizado

Além de uma string ou lista de roles, `authenticate` aceita uma instância de
`AuthorizationValidator`. Isso permite validar flags ou qualquer informação do
`AuthContext` sem transformar a regra em uma role artificial:

```php
use Daniel\HttpSecurity\AuthContext;
use Daniel\HttpSecurity\AuthorizationValidator;

final class SystemAdministratorValidator extends AuthorizationValidator
{
    public function isValid(AuthContext $context): bool
    {
        $principal = $context->getUserArgs()['principal'] ?? [];
        return ($principal['systemAdministrator'] ?? false) === true;
    }
}

$security->Request('/system/**')
    ->authenticate(new SystemAdministratorValidator());

// As formas anteriores continuam válidas:
$security->Request('/reports')->authenticate('report.view');
$security->Request('/financial')->authenticate(['fin.list', 'fin.process']);
```

## Contribuição

Sinta-se à vontade para abrir issues e enviar pull requests. Toda contribuição é bem-vinda!
