package rs.make.alfresco.account;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.repository.StoreRef;
import org.alfresco.service.cmr.search.ResultSet;
import org.alfresco.service.cmr.search.SearchService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;
import rs.make.alfresco.common.webscripts.MakeCommonHelpers;
import rs.make.alfresco.globalproperties.GlobalProperties;

public class RequestResetAuthentication extends DeclarativeWebScript {

	protected MakeStatus makeStatus;
	public MakeStatus getMakeStatus() {
		return makeStatus;
	}
	public void setMakeStatus( MakeStatus makeStatus ) {
		this.makeStatus = makeStatus;
	}

	protected MakeCommonHelpers makeCommonHelpers;
	public MakeCommonHelpers getMakeCommonHelpers() {
		return makeCommonHelpers;
	}
	public void setMakeCommonHelpers( MakeCommonHelpers makeCommonHelpers ) {
		this.makeCommonHelpers = makeCommonHelpers;
	}

	protected MutableAuthenticationService authenticationService;
	public MutableAuthenticationService getAuthenticationService() {
		return authenticationService;
	}
	public void setAuthenticationService( MutableAuthenticationService authenticationService ) {
		this.authenticationService = authenticationService;
	}

	protected PersonService personService;
	public PersonService getPersonService() {
		return personService;
	}
	public void setPersonService( PersonService personService ) {
		this.personService = personService;
	}

	protected NodeService nodeService;
	public NodeService getNodeService() {
		return nodeService;
	}
	public void setNodeService( NodeService nodeService ) {
		this.nodeService = nodeService;
	}

	protected SearchService searchService;
	public SearchService getSearchService() {
		return searchService;
	}
	public void setSearchService( SearchService searchService ) {
		this.searchService = searchService;
	}

	protected GlobalProperties globalProperties;
	public GlobalProperties getGlobalProperties() {
		return globalProperties;
	}
	public void setGlobalProperties( GlobalProperties globalProperties ) {
		this.globalProperties = globalProperties;
	}

	private final String REQUIRED_TOKEN_NAME = "requiredToken";
	private final QName REQUIRED_TOKEN = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , REQUIRED_TOKEN_NAME );
	private final String TOKEN_VALIDITY_NAME = "tokenValidity";
	private final QName TOKEN_VALIDITY = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , TOKEN_VALIDITY_NAME );

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;
	private final String JSON_EMAIL_KEY = "email";

	private static Logger logger = Logger.getLogger( RequestResetAuthentication.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			JSONObject requestJSON = makeCommonHelpers.validateJSONRequest( req , message , status );
			String email = makeCommonHelpers.getString( requestJSON , JSON_EMAIL_KEY , message , status , true );
			EmailValidator emailValidator = EmailValidator.getInstance( false );
			if( !emailValidator.isValid( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameIsNotEmail" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			AuthenticationUtil.setRunAsUserSystem();

			if( !checkIsEmailExisting( email ) || !authenticationService.authenticationExists( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			NodeRef person = personService.getPerson( email );
			if( person == null ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.personDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			Date tokenValidity = DateUtils.addDays( ( new Date() ) , 1 );
			nodeService.setProperty( person , TOKEN_VALIDITY , tokenValidity );
			SimpleDateFormat dateFormat = new SimpleDateFormat( "dd.MM.yyyy HH:mm:ss" );
			String formattedTokenValidity = dateFormat.format( tokenValidity );

			String token = UUID.randomUUID().toString();
			nodeService.setProperty( person , REQUIRED_TOKEN , token );

			String applicationServer = globalProperties.getProperty( "wbif.application.URI" );
			if( applicationServer == null ){
				String errorMessage = message.get( "error.WBIFApplicationURINotDefined" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}
			String from = globalProperties.getProperty( "mail.from.default" );
			if( from == null ){
				String errorMessage = message.get( "error.fromEmailNotDefined" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}
			ArrayList<String> subjectargs = new ArrayList<String>();
			subjectargs.add( (String) nodeService.getProperty( person, ContentModel.PROP_FIRSTNAME ) );
			subjectargs.add( (String) nodeService.getProperty( person, ContentModel.PROP_LASTNAME ) );
			subjectargs.add( email );
			String subject = message.get( "email.subject" , subjectargs );
			ArrayList<String> bodyargs = new ArrayList<String>();
			bodyargs.add( applicationServer );
			bodyargs.add( (String) nodeService.getProperty( person, ContentModel.PROP_FIRSTNAME ) );
			bodyargs.add( (String) nodeService.getProperty( person, ContentModel.PROP_LASTNAME ) );
			bodyargs.add( email );
			bodyargs.add( token );
			bodyargs.add( formattedTokenValidity );
			String body = message.get( "email.body" , bodyargs );

			NodeRef template = null;
			Map<String, Serializable> templateArgs = new HashMap<String, Serializable>();
			String templateStr = message.get( "email.template" , null );
			if( templateStr != null ){
				ResultSet resultSet = searchService.query( StoreRef.STORE_REF_WORKSPACE_SPACESSTORE , SearchService.LANGUAGE_LUCENE , templateStr );
				if ( resultSet.length() > 0 ) {
					template = resultSet.getNodeRef(0);
					templateArgs.put( "applicationServer" , applicationServer );
					templateArgs.put( "firstName" , (String) nodeService.getProperty( person, ContentModel.PROP_FIRSTNAME ) );
					templateArgs.put( "lastName" , (String) nodeService.getProperty( person, ContentModel.PROP_LASTNAME ) );
					templateArgs.put( "email" , email );
					templateArgs.put( "token" , token );
					templateArgs.put( "tokenValidity" , formattedTokenValidity );
				}
			}

			makeCommonHelpers.sendEmail( person , email , from , subject , body , template , templateArgs , message );

			AuthenticationUtil.clearCurrentSecurityContext();

			model.put( "response", email );
			ArrayList<String> args = new ArrayList<String>(1);
			args.add( email );
			String parsedMessage = message.get( "success.text" , args );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + RequestResetAuthentication.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + RequestResetAuthentication.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + RequestResetAuthentication.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + RequestResetAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + RequestResetAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , RequestResetAuthentication.class );
			return null;
		}
		return model;
	}

	private boolean checkIsEmailExisting( String email ) throws Exception{
		boolean existing = false;

		List<QName> lookFor = new ArrayList<QName>(1);
		lookFor.add( ContentModel.PROP_EMAIL );
		List<Pair<QName,Boolean>> sortProps = new ArrayList<Pair<QName,Boolean>>(1);
		Pair<QName,Boolean> emailSort = new Pair<QName,Boolean>( ContentModel.PROP_EMAIL , true );
		sortProps.add( emailSort );
		PagingRequest pagingRequest = new PagingRequest( 2 );
		PagingResults<PersonService.PersonInfo> persons = personService.getPeople( email , lookFor , sortProps , pagingRequest );

		int resultSize = persons.getPage().size();
		if( resultSize > 0 ) existing = true;

		return existing;
	}
}
