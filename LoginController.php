<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Ramsey\Uuid\Uuid;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Str;
use Pterodactyl\Services\Users\UserCreationService;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Laravel\Socialite\Facades\Socialite;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;
use Pterodactyl\Models\User;

class LoginController extends AbstractLoginController
{
    private ViewFactory $view;
    
    private $creationService;

    /**
     * LoginController constructor.
     */
    public function __construct(ViewFactory $view, UserCreationService $creationService) {
        parent::__construct();

        $this->view = $view;
        $this->creationService = $creationService;
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component. Vuejs will take over at this point and
     * turn the login area into a SPA.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function index(): View
    {
        return $this->view->make('templates/auth.core');
    }

    /**
     * Handle a login request to the application.
     *
     * @return \Illuminate\Http\JsonResponse|void
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        try {
            $username = $request->input('user');

            /** @var \Pterodactyl\Models\User $user */
            $user = User::query()->where($this->getField($username), $username)->firstOrFail();
        } catch (ModelNotFoundException $exception) {
            $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceede to the next step in the login process.
        if (!password_verify($request->input('password'), $user->password)) {
            $this->sendFailedLoginResponse($request, $user);
        }

        if ($user->use_totp) {
            $token = Str::random(64);

            $request->session()->put('auth_confirmation_token', [
                'user_id' => $user->id,
                'token_value' => $token,
                'expires_at' => CarbonImmutable::now()->addMinutes(5),
            ]);

            return new JsonResponse([
                'data' => [
                    'complete' => false,
                    'confirmation_token' => $token,
                ],
            ]);
        }

        $this->auth->guard()->login($user, true);

        return $this->sendLoginResponse($user, $request);
    }

    public function redirectToProvider($provider): JsonResponse
    {
        return new JsonResponse(['redirect' => Socialite::driver($provider)->setScopes(['openid', 'email', 'profile'])->redirect()->getTargetUrl()]);
    }

    public function handleProviderCallback(Request $request, $provider)
    {
        try {
            $user = Socialite::driver($provider)->user();
        } catch (\Exception $e) {
	    logger()->error($e);
            return Redirect::route('auth.login');
        }

        $authUser = $this->findOrCreateUser($user);

        if (! $authUser) {
            return Redirect::route('auth.login');
        }

        Auth::login($authUser, true);

        return Redirect::route('index');
    }

    protected function findOrCreateUser($oauthUser)
    {
        if ($authUser = User::query()->where('whmcs_user_token', $oauthUser->id)->first()) {
            return $authUser;
        }

        if($authUser = User::query()->where('email', $oauthUser->email)->first()) {
            $authUser->update([
                'whmcs_user_token' => $oauthUser->id
            ]);

            return $authUser;
        }

        return $this->creationService->handle([
            'username' => Str::random(8),
            'email' => $oauthUser->email,
            'name_first' => $oauthUser->name_first,
            'name_last' => $oauthUser->name_last,
            'whmcs_user_token' => $oauthUser->id,
        ]);
    }
}
