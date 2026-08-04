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
        return in_array('SYSTEM_ADMINISTRATOR', $context->getRoles(), true);
    }
}

$security->Request('/system/**')
    ->authenticate(new SystemAdministratorValidator());

// As formas anteriores continuam válidas:
$security->Request('/reports')->authenticate('report.view');
$security->Request('/financial')->authenticate(['fin.list', 'fin.process']);
```

## Autorização por atributo

Controllers e endpoints também podem declarar a mesma regra de autorização
com `#[Autorize]`. O argumento aceita uma role, uma lista de roles ou uma
instância de `AuthorizationValidator`, exatamente como `authenticate`:

```php
use Daniel\HttpSecurity\Annotations\Autorize;

#[Autorize('laudo.view')]
final class LaudoController
{
    #[Autorize(['laudo.create', 'laudo.update'])]
    public function save(): void
    {
    }

    #[Autorize(new SystemAdministratorValidator())]
    public function systemConfiguration(): void
    {
    }
}
```

O atributo pode ser aplicado na classe ou no método. Quando ambos estiverem
presentes, a regra do método substitui a regra da classe. O nome em inglês
`#[Authorize]` também está disponível como alias.

## Contribuição

Sinta-se à vontade para abrir issues e enviar pull requests. Toda contribuição é bem-vinda!
