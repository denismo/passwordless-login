%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 14. Nov 2013 10:07 PM
%%%-------------------------------------------------------------------

%% API
-record(target2sts,{targetID,userName, reason, requestID, targetsSignature}).
-record(sts2authenticator, {targetName, requestID, userName, reason, stsID, stsSignature}).
-record(authenticator2sts, {requestID, decision, authenticatorSignature}).
-record(authenticator2stsLogin, {userName, password, authCertificate}).

