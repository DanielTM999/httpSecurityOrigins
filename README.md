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

## Persistência do contexto de autenticação

A política (`SessionPolice`), o armazenamento (`StatefulStorage`) e o codec
(`AuthContextCodec`) são configurados separadamente:

| Configuração | Comportamento |
|---|---|
| `STATELESS` (padrão) | Contexto apenas em memória durante a requisição; armazenamento e codec não são usados. |
| `STATEFULL` + `SESSION` (padrão do STATEFULL) | Contexto na sessão PHP, chave `Securitycontext`. |
| `STATEFULL` + `COOKIE` | Contexto em cookie cifrado e autenticado (AES-256-GCM). |

Nenhuma alteração em `AuthContext`, filtros, login (`SecurityContext::setContext`)
ou logout (`SecurityContext::clearContext`) é necessária para trocar o armazenamento.

### Sessão PHP

```php
use Daniel\HttpSecurity\SessionPolice;
use Daniel\HttpSecurity\StatefulStorage;

$httpManager->sessionPolice(SessionPolice::STATEFULL);

$httpManager->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::SESSION);
```

Com o codec interno a sessão continua guardando exatamente `serialize($context)`,
então sessões criadas por versões anteriores são lidas sem migração.

### Cookie

```php
use Daniel\HttpSecurity\CookieOptions;
use Daniel\HttpSecurity\SessionPolice;
use Daniel\HttpSecurity\StatefulStorage;

$httpManager
    ->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE)
    ->cookieOptions(new CookieOptions(
        name: 'app_auth',
        ttl: 60 * 60 * 8,
        path: '/',
        sameSite: 'Strict'
    ));
```

O mesmo resultado pode ser obtido pelo `.env` lido pelo Origins:

```dotenv
HTTP_SECURITY_STATEFUL_STORAGE=cookie
HTTP_SECURITY_COOKIE_KEY=coloque-aqui-a-chave-base64
HTTP_SECURITY_COOKIE_NAME=http_security_context
HTTP_SECURITY_COOKIE_TTL=2592000
HTTP_SECURITY_COOKIE_PATH=/
HTTP_SECURITY_COOKIE_DOMAIN=
HTTP_SECURITY_COOKIE_SECURE=true
HTTP_SECURITY_COOKIE_SAME_SITE=Lax
```

| Variável | Padrão |
|---|---|
| `HTTP_SECURITY_STATEFUL_STORAGE` | `session` |
| `HTTP_SECURITY_COOKIE_NAME` | `http_security_context` |
| `HTTP_SECURITY_COOKIE_TTL` | `2592000` (30 dias) |
| `HTTP_SECURITY_COOKIE_KEY` | obrigatória no modo cookie |
| `HTTP_SECURITY_COOKIE_PATH` | `/` |
| `HTTP_SECURITY_COOKIE_DOMAIN` | vazio (sem `Domain`) |
| `HTTP_SECURITY_COOKIE_SECURE` | `true` |
| `HTTP_SECURITY_COOKIE_SAME_SITE` | `Lax` |

Precedência: valor explícito no código > `$_ENV` > padrão. O segundo argumento de
`sessionPolice` equivale a `statefulStorage()`, e a última escolha explícita prevalece.
O cookie é sempre `HttpOnly`; `SameSite=None` exige `Secure`. Configurações inválidas
geram `InvalidArgumentException` no modo `STATEFULL` + `COOKIE`, sem retorno silencioso
para a sessão.

#### Chave

A chave deve ser base64 de exatamente 32 bytes. Gere-a uma única vez:

```bash
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

Guarde-a de forma estável, fora do controle de versão (por exemplo no `.env` de cada
servidor), e use a mesma chave em todas as instâncias da aplicação. Nunca gere a chave
por requisição. A chave é exclusiva da autenticação: quem tiver acesso a ela consegue
produzir cookies aceitos pela aplicação.

#### Desenvolvimento em HTTP

Navegadores não devolvem cookies `Secure` em `http://`. Em desenvolvimento local
desative explicitamente:

```php
$httpManager->cookieOptions(new CookieOptions(secure: false));
```

ou `HTTP_SECURITY_COOKIE_SECURE=false` no `.env` de desenvolvimento.

#### Migração da sessão para o cookie

Ao ativar o modo cookie, se a requisição não trouxer o cookie e a sessão ainda tiver um
contexto válido, ele é decodificado, o cookie é emitido e somente então
`Securitycontext` é removido da sessão. Um cookie recebido inválido, adulterado ou
expirado retorna `null`, tenta excluir o cookie e não volta para a sessão.

### Codec personalizado (opcional)

Por padrão é usado `PhpSerializedAuthContextCodec`, que preserva a classe concreta,
propriedades privadas e `readonly` e objetos de data. Um codec personalizado vale tanto
para sessão quanto para cookie:

```php
use Daniel\HttpSecurity\AuthContext;
use Daniel\HttpSecurity\AuthContextCodec;

final class UserDetailsJsonCodec implements AuthContextCodec
{
    public function encode(AuthContext $context): string
    {
        return json_encode([
            'user' => $context->getUser(),
            'roles' => $context->getRoles(),
            'environment' => $context->getEnvironment(),
        ], JSON_THROW_ON_ERROR);
    }

    public function decode(string $data): AuthContext
    {
        $value = json_decode($data, true, 8, JSON_THROW_ON_ERROR);
        return new UserDetails($value['user'], $value['roles'], $value['environment']);
    }
}

$httpManager
    ->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE)
    ->contextCodec(new UserDetailsJsonCodec());
```

O codec só converte o contexto em string e de volta; não controla armazenamento,
criptografia, validade ou cabeçalhos, e não substitui a proteção do cookie. Ele é
configurado apenas por instância, nunca por nome de classe vindo do ambiente. Se
`decode` lançar exceção, o contexto é descartado e `getContext()` retorna `null`. Para
continuar lendo sessões antigas após trocar o codec, o próprio `decode` pode aceitar o
formato anterior.

### Observações e limitações

- O cookie tem validade absoluta (`TTL`, 30 dias por padrão). A leitura não renova o
  prazo; cada `setContext` emite um novo cookie com novo prazo.
- O cookie não prolonga nada no backend: filtros continuam responsáveis por revogar
  usuários (por exemplo, bloqueados) chamando `SecurityContext::clearContext()`.
- Apenas o contexto de autenticação é restaurado pelo cookie; outras chaves de
  `$_SESSION` continuam dependendo da sessão PHP.
- O cabeçalho `Set-Cookie` completo é limitado a 4096 bytes. Contextos maiores geram
  `LengthException` antes de substituir o contexto atual; um codec mais compacto resolve.
- Trocar a chave ou o codec pode exigir novo login.
- `clearContext()` remove o contexto da memória, a cópia legada da sessão e o cookie do
  navegador atual. Cópias antigas do cookie em outros navegadores só deixam de valer pela
  expiração ou por revogação no filtro (não há repositório de revogação).
- Falhas de escrita (`setContext`) lançam exceção e não alteram o contexto atual; falhas
  de leitura invalidam o contexto e retornam `null`.

## Contribuição

Sinta-se à vontade para abrir issues e enviar pull requests. Toda contribuição é bem-vinda!
