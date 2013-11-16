%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:50 PM
%%%-------------------------------------------------------------------
-module(sts).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2, code_change/3]).
-include("records.erl").

init(_Args) -> {ok,[]}.

handle_info(Msg, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {noreply, State}.

handle_cast(stop, State) ->
  {stop, normal, State}.

terminate(normal, _State) ->
  io:format("Stopping the server~n"),
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

handle_call(terminate, _From, State) ->
  {stop, normal, ok, State};

handle_call({verify,Claims}, _From, State) ->
  io:format("STS: Verifying: ~p~n",[Claims]),
  try
    Target = auth_security:extract_claim(Claims, target),
    verify_signature(Claims,Target),
    Target /= invalid,
    Username = auth_security:extract_claim(Claims, user),
    Username /= invalid,
    Reply = confirm_user(Username, Target),
    case Reply of
      [{confirmed, Claims}|_] ->
        io:format("STS: Verified: ~p~n",[Claims]),
        {reply, auth_security:sign([Claims,{verify,confirmed}]), State};
      _ -> throw(denied)
    end
  catch _ ->
    io:format("STS: Denied: ~p~n",[Claims]),
    {reply, auth_security:sign([{verify,invalid}]), State}
  end;
handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

verify_signature(_Claims,_Authority) ->
  % TODO Implement signature verification
  ok.

%%   if
%%     validate_stateless_claims(Claims) ->
%%       Reply = validate_remote_claims(Claims),
%%       {reply, Reply, state};
%%     true -> {reply, invalid, State}
%%   end.

% TODO Some claims are required, need to ensure they are present
%% validate_stateless_claims([Claim|T]) ->
%%   case Claim of
%%     {claim,target,Token} -> validate_target_token(Token);
%%     _ -> false
%%   end,
%%   validate_stateless_claims(T);
%% validate_stateless_claims([]) -> true.
%%
%% validate_target_token(Token) ->
%%   case Token of
%%     {valid_token,Target} ->
%%       % TODO Validate token based on previous registration
%%       io:format("Validated target ~p token", [Target]),
%%       true;
%%     _ -> false
%%   end.

%% validate_remote_claims([Claim|T]) ->
%%   case Claim of
%%     {claim,user,Username} -> confirm_user(Username);
%%     _ -> false
%%   end,
%%   validate_remote_claims(T);
%%  validate_remote_claims([]) -> true.

confirm_user(Username, Target) ->
  Authenticator = user_authenticator(Username),
  gen_server:call(Authenticator, {confirm, auth_security:sign([{claim,user,Username}, {claim,target,Target}])}).

user_authenticator(_Username) ->
  % TODO Authenticator per user
  authenticator_server.

