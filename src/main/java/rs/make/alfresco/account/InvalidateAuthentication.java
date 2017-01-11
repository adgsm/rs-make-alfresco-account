package rs.make.alfresco.account;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.apache.log4j.Logger;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;

public class InvalidateAuthentication extends DeclarativeWebScript {

	protected MakeStatus makeStatus;
	public MakeStatus getMakeStatus() {
		return makeStatus;
	}
	public void setMakeStatus( MakeStatus makeStatus ) {
		this.makeStatus = makeStatus;
	}

	protected AuthenticationService authenticationService;
	public AuthenticationService getAuthenticationService() {
		return authenticationService;
	}
	public void setAuthenticationService( AuthenticationService authenticationService ) {
		this.authenticationService = authenticationService;
	}

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;

	private static Logger logger = Logger.getLogger( InvalidateAuthentication.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUser = AuthenticationUtil.getFullyAuthenticatedUser();

			String token = authenticationService.getCurrentTicket();
			try{
				authenticationService.invalidateTicket( token );
				AuthenticationUtil.setRunAsUserSystem();
				authenticationService.invalidateUserSession( authenticatedUser );
				AuthenticationUtil.clearCurrentSecurityContext();
			}
			catch( AuthenticationException ae ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( token );
				String errorMessage = message.get( "error.invalidToken" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_NOT_FOUND ) ) );
			}

			logger.debug( "Successfully invalidated current authenticaion ticket for user \"" + authenticatedUser + "\"." );
			model.put( "response", true );
			String parsedMessage = message.get( "success.text" , null );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + InvalidateAuthentication.class.getName() + "] Error message" + e.getMessage() );
				logger.debug( "[" + InvalidateAuthentication.class.getName() + "] Error cause" + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + InvalidateAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + InvalidateAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , InvalidateAuthentication.class );
			return null;
		}
		return model;
	}

}
