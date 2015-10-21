//
//  Connection.cpp
//  DXMPP
//
//  Created by Stefan Karlsson on 31/05/14.
//  Copyright (c) 2014 Deus ex Machinae. All rights reserved.
//


#include "Connection.hpp"


#include <boost/thread.hpp>

#include <iostream>

#include <DXMPP/SASL/SASLMechanism.hpp>
#include <DXMPP/SASL/SASLMechanism_DIGEST_MD5.hpp>
#include <DXMPP/SASL/SASLMechanism_SCRAM_SHA1.hpp>
#include <DXMPP/SASL/SASLMechanism_PLAIN.hpp>
#include <xercesc/sax2/XMLReaderFactory.hpp>
#include <xercesc/sax2/SAX2XMLReader.hpp>
#include <xercesc/sax2/DefaultHandler.hpp>
#include <xercesc/sax2/Attributes.hpp>

namespace DXMPP
{

#define DebugOut(DebugLevel) \
if (DebugLevel > DebugTreshold) {} \
else std::cout

    using namespace std;
    using namespace pugi;
    using namespace xercesc;


    void Connection::BrodcastConnectionState(ConnectionCallback::ConnectionState NewState)
    {
        if(PreviouslyBroadcastedState == NewState)
            return;
        PreviouslyBroadcastedState = NewState;

        if(!ConnectionHandler)
            return;

        ConnectionHandler->ConnectionStateChanged(NewState, shared_from_this());
    }

    void Connection::startElement(
            const   XMLCh* const    uri,
            const   XMLCh* const    localname,
            const   XMLCh* const    qname,
            const   xercesc::Attributes&     attrs
        )
    {
        char* tagname = XMLString::transcode(localname);
        if(ActiveDocument == nullptr)
        {
            ActiveDocument.reset( new pugi::xml_document() );
        }
        pugi::xml_node NewNode = ActiveDocument->append_child(tagname);
        ActiveDocumentNodes.push(NewNode);

        //cout << "<" << tagname;
        // Attributes
        for( XMLSize_t i = 0; i < attrs.getLength(); i++ )
        {
            char *AttrName = XMLString::transcode(attrs.getLocalName(i) );
            char *AttrValue= XMLString::transcode(attrs.getValue(i) );

            //cout << " " << AttrName << "=\"" << AttrValue << "\"";

            pugi::xml_attribute NewAttribute = NewNode.append_attribute(AttrName);

            NewAttribute.set_value(AttrValue);

            XMLString::release(&AttrName);
            XMLString::release(&AttrValue);
        }

        //cout << ">";
        XMLString::release(&tagname);
    }

    void Connection::endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname)
    {
        char* tagname = XMLString::transcode(localname);
        if( strncmp(tagname, "</stream:stream>", sizeof("</stream:stream>")) == 0 )
        {
            std::cerr << "Got end of stream from xmppserver" << std::endl;
            Client->ClearReadDataStream();
            CurrentConnectionState = ConnectionState::ErrorUnknown;
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
            DebugOut(DebugOutputTreshold::Debug) << "Got stream end" << std::endl;
        }

        //cout << "</" << tagname << ">" << std::endl;
        XMLString::release(&tagname);

        ActiveDocumentNodes.pop();
        if( ActiveDocumentNodes.size() == 0 )
        {
            CheckStreamForValidXML();
        }
    }

    void Connection::characters(const XMLCh* const chars, const XMLSize_t length)
    {
       char* Data = XMLString::transcode(chars);
       //cout << "+++" << Data << "---";
       pugi::xml_node &ActiveNode = ActiveDocumentNodes.back();
       std::string Temp = std::string(ActiveNode.text().as_string()) + std::string(Data);
       ActiveNode.set_value( Temp.c_str() );
       XMLString::release(&Data);
    }


    void Connection::fatalError(const xercesc::SAXParseException& ex)
    {
        std::cerr << "Got sax exception: " << ex.getMessage() << std::endl;
    }

    void Connection::OpenXMPPStream()
    {
        CurrentConnectionState = ConnectionState::WaitingForFeatures;

        stringstream Stream;
        Stream << "<?xml version='1.0' encoding='utf-8'?>" << std::endl;
        Stream << "<stream:stream" << endl;
        Stream << " from = '" << MyJID.GetBareJID() << "'" << endl;
        Stream << " to = '" << MyJID.GetDomain() << "'" << endl;
        Stream << " version='1.0'" << endl;
        Stream << " xml:lang='en'" << endl;
        Stream << " xmlns='jabber:client'" << endl;
        Stream << " xmlns:stream='http://etherx.jabber.org/streams'>";

        DebugOut(DebugOutputTreshold::Debug)
            << "DXMPP: Opening stream" << std::endl;// << Stream.str();

        Client->WriteTextToSocket(Stream.str());
    }

    void Connection::CheckStreamForFeatures()
    {
        string str = Client->ReadDataStream->str();
        size_t streamfeatures = str.find("</stream:features>");

        if(streamfeatures == string::npos)
            return;

        if(CurrentAuthenticationState == AuthenticationState::SASL)
        {
            Client->ClearReadDataStream();
            CurrentConnectionState = ConnectionState::Authenticating;
            return;
        }
        if(CurrentAuthenticationState == AuthenticationState::Bind)
        {
            Client->ClearReadDataStream();
            CurrentConnectionState = ConnectionState::Authenticating;
            BindResource();
            return;
        }

        // note to self: cant use loadxml() here because this is not valid xml!!!!
        // due to <stream> <stream::features></stream::features>
        xml_document xdoc;
        xdoc.load(*Client->ReadDataStream, parse_full&~parse_eol, encoding_auto);

        Client->ClearReadDataStream();

        ostringstream o;

        xdoc.save(o, "\t", format_no_declaration);

        pugi::xpath_node starttls = xdoc.select_single_node("//starttls");
        if(starttls)
        {
            DebugOut(DebugOutputTreshold::Debug)
                << std::endl << "START TLS SUPPORTED" << std::endl;
            FeaturesStartTLS = true;
        }

        //Move to sasl class
        pugi::xpath_node_set mechanisms = xdoc.select_nodes("//mechanism");
        for (auto it = mechanisms.begin(); it != mechanisms.end(); it++)
        {
            xml_node node = it->node();
            string mechanism = string(node.child_value());
            DebugOut(DebugOutputTreshold::Debug)
                << "Mechanism supported: " << mechanism << std::endl;


            if(mechanism == "DIGEST-MD5")
                FeaturesSASL_DigestMD5 = true;
            if(mechanism == "CRAM-MD5")
                FeaturesSASL_CramMD5 = true;
            if(mechanism == "SCRAM-SHA-1")
                FeaturesSASL_ScramSHA1 = true;
            if(mechanism == "PLAIN")
                FeaturesSASL_Plain = true;

        }

        CurrentConnectionState = ConnectionState::Authenticating;

        // If start tls: initiate shit/restart stream

        if(CurrentAuthenticationState != AuthenticationState::StartTLS)
        {
            if(FeaturesStartTLS)
            {
                CurrentAuthenticationState = AuthenticationState::StartTLS;

                DebugOut(DebugOutputTreshold::Debug) << "Initializing TLS" << std::endl;

                stringstream Stream;
                Stream << "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
                Client->WriteTextToSocket(Stream.str());
                return;
            }
        }
        CurrentAuthenticationState = AuthenticationState::SASL;


        DebugOut(DebugOutputTreshold::Debug) << "SASL MANDLEBRASL" << std::endl;
        // I shall has picked an algorithm!

        if(FeaturesSASL_ScramSHA1)
        {
            Authentication = new  SASL::SASL_Mechanism_SCRAM_SHA1 ( Client, MyJID, Password),
            Authentication->Begin();
            return;
        }
        if(FeaturesSASL_DigestMD5)
        {
            Authentication = new  SASL::Weak::SASL_Mechanism_DigestMD5 ( Client , MyJID, Password),
            Authentication->Begin();
            return;
        }
        if(FeaturesSASL_Plain)
        {
            Authentication = new  SASL::Weak::SASL_Mechanism_PLAIN ( Client , MyJID, Password),
            Authentication->Begin();
            return;
        }
    }


    void Connection::InitTLS()
    {
        DebugOut(DebugOutputTreshold::Debug)
            << "Server accepted to start TLS handshake" << std::endl;
        bool Success = Client->ConnectTLSSocket();
        if(Success)
        {
            DebugOut(DebugOutputTreshold::Debug)
                << "TLS Connection successfull. Reopening stream." << std::endl;
            OpenXMPPStream();
        }
        else
        {
            std::cerr << "TLS Connection failed" << std::endl;
            CurrentConnectionState = ConnectionState::ErrorUnknown;
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
        }

    }

    void Connection::CheckForTLSProceed(pugi::xml_document* Doc)
    {
        if(!Doc->select_single_node("//proceed").node())
        {
            std::cerr << "No proceed tag; B0rked SSL?!";

            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
            CurrentConnectionState = ConnectionState::ErrorUnknown;
            return;
        }

        if(CurrentAuthenticationState == AuthenticationState::StartTLS)
            InitTLS();
    }

    void Connection::CheckForWaitingForSession(pugi::xml_document* Doc)
    {
        xml_node iqnode = Doc->select_single_node("//iq").node();

        if(!iqnode)
        {
            std::cerr << "No iqnode?!";
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
            CurrentConnectionState = ConnectionState::ErrorUnknown;

            return;
        }

        // TODO: Verify iq response..

        string Presence = "<presence/>";

        Client->WriteTextToSocket(Presence);
        CurrentConnectionState = ConnectionState::Connected;
        Client->SetKeepAliveByWhiteSpace(string(" "), 5);
        DebugOut(DebugOutputTreshold::Debug) << std::endl << "ONLINE" << std::endl;
    }

    void Connection::CheckForBindSuccess(pugi::xml_document* Doc)
    {
        xml_node iqnode = Doc->select_single_node("//iq").node();

        if(!iqnode)
        {
            std::cerr << "No iqnode?!";
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
            CurrentConnectionState = ConnectionState::ErrorUnknown;

            return;
        }

        DebugOut(DebugOutputTreshold::Debug)
                << std::endl
                << "AUTHENTICATED"
                << std::endl; // todo: verify xml ;)

        string StartSession = "<iq type='set' id='1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>";
        Client->WriteTextToSocket(StartSession);
        CurrentConnectionState = ConnectionState::WaitingForSession;
        CurrentAuthenticationState = AuthenticationState::Authenticated;
    }

    void Connection::BindResource()
    {
        // TODO: Make Proper XML ?
        //bind resource..
        stringstream TStream;
        TStream << "<iq type='set' id='bindresource'>";
        TStream << "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>";
        TStream << "<resource>" << MyJID.GetResource() << "</resource>";
        TStream << "</bind>";
        TStream << "</iq>";
        Client->WriteTextToSocket(TStream.str());
    }

    void Connection::StartBind()
    {
        CurrentAuthenticationState = AuthenticationState::Bind;
        OpenXMPPStream();
    }

    void Connection::CheckForSASLData(pugi::xml_document* Doc)
    {
        xml_node challenge = Doc->select_single_node("//challenge").node();
        xml_node success = Doc->select_single_node("//success").node();

        if(!challenge && !success)
        {
            std::cerr << "Bad authentication." << std::endl;
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorAuthenticating);
            CurrentConnectionState = ConnectionState::ErrorAuthenticating;

            return;
        }

        if(challenge)
        {
            Authentication->Challenge(challenge);
            return;
        }

        if(success)
        {
            if( !Authentication->Verify(success) )
            {
                std::cerr << "Bad success verification from server" << std::endl;
                BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorAuthenticating);
                CurrentConnectionState = ConnectionState::ErrorAuthenticating;

                return;
            }
            DebugOut(DebugOutputTreshold::Debug)
                    <<
                       std::endl
                    << "Authentication succesfull."
                    << std::endl;
            StartBind();
        }
    }

    void Connection::CheckStreamForAuthenticationData(pugi::xml_document* Doc)
    {
        switch(CurrentAuthenticationState)
        {
            case AuthenticationState::StartTLS:
                CheckForTLSProceed(Doc);
                break;
            case AuthenticationState::SASL:
                CheckForSASLData(Doc);
                break;
            case AuthenticationState::Bind:
                CheckForBindSuccess(Doc);
                break;
            case AuthenticationState::Authenticated:
                break;
        default:
            break;
        }

    }

    bool Connection::CheckStreamForStanza(pugi::xml_document* Doc)
    {
        xml_node message = Doc->select_single_node("//message").node();

        if(!message)
            return false;

        return true;
    }

    void Connection::DispatchStanza(std::unique_ptr<pugi::xml_document> Doc)
    {
        xml_node message = Doc->select_single_node("//message").node();
        if(StanzaHandler)
            StanzaHandler->StanzaReceived(
                        SharedStanza(
                            new Stanza( std::move(Doc),
                                       message)),
                        shared_from_this());
    }

    void Connection::CheckForPresence(pugi::xml_document* Doc)
    {
        xml_node presence = Doc->select_single_node("//presence").node();

        if(!presence)
            return;

        Roster->OnPresence(presence);
    }


    SharedStanza Connection::CreateStanza(const JID &TargetJID)
    {
        SharedStanza ReturnValue(new Stanza());
        ReturnValue->To = TargetJID;
        ReturnValue->From = MyJID;
        return ReturnValue;
    }

    void Connection::SendStanza(SharedStanza Stanza)
    {
        if(this->CurrentConnectionState != ConnectionState::Connected)
        {
            throw std::runtime_error("Trying to send Stanza with disconnected connection.");
        }

        switch(Stanza->Type)
        {
        case StanzaType::Chat:
            Stanza->Message.attribute("type").set_value( "chat" );
            break;
        case StanzaType::Error:
            Stanza->Message.attribute("type").set_value( "error" );
            break;
        }

        Stanza->Message.attribute("from").set_value( MyJID.GetFullJID().c_str() );
        Stanza->Message.attribute("to").set_value( Stanza->To.GetFullJID().c_str() );

        Client->WriteXMLToSocket(Stanza->Document.get());
    }

    void Connection::CheckStreamForValidXML()
    {
        if(CurrentConnectionState == ConnectionState::WaitingForFeatures)
        {
            BrodcastConnectionState(ConnectionCallback::ConnectionState::Connecting);
            CheckStreamForFeatures();
            return;
        }        

        std::unique_ptr<pugi::xml_document> Document = nullptr;
        {
            boost::unique_lock<boost::shared_mutex> Lock(ActiveDocumentMutex);

            if(ActiveDocument == nullptr)
            {
                std::cout << "Active document is nullptr?" << std::endl;
                return;
            }

            Document = std::move(ActiveDocument);
            ActiveDocument = nullptr;
        }


        switch(CurrentConnectionState)
        {
            case ConnectionState::WaitingForSession:
                BrodcastConnectionState(ConnectionCallback::ConnectionState::Connecting);
                CheckForWaitingForSession(Document.get());
                break;
            case ConnectionState::WaitingForFeatures:
                break;
            case ConnectionState::Authenticating:
                BrodcastConnectionState(ConnectionCallback::ConnectionState::Connecting);
                CheckStreamForAuthenticationData(Document.get());
                break;
            case ConnectionState::Connected:
                BrodcastConnectionState(ConnectionCallback::ConnectionState::Connected);
                CheckForPresence(Document.get());
                if(CheckStreamForStanza(Document.get()))
                {
                    DispatchStanza(std::move(Document));
                }
                break;
        default:
            break;
        }

        //CheckForStreamEnd();
    }

    void Connection::Reset()
    {
        FeaturesSASL_CramMD5 = false;
        FeaturesSASL_DigestMD5 = false;
        FeaturesSASL_Plain = false;
        FeaturesSASL_ScramSHA1 = false;
        FeaturesStartTLS = false;
        CurrentAuthenticationState = AuthenticationState::None;

        if(Authentication != nullptr)
        {
            Authentication = nullptr;
            delete Authentication;
        }

    }

    void Connection::Reconnect()
    {
        Reset();
        Connect();
    }

    Connection::Connection(const std::string &Hostname,
        int Portnumber,
        const JID &RequestedJID,
        const std::string &Password,
        ConnectionCallback *ConnectionHandler,
        StanzaCallback *StanzaHandler,
        PresenceCallback *PresenceHandler,
        SubscribeCallback *SubscribeHandler,
        SubscribedCallback *SubscribedHandler,
        UnsubscribedCallback *UnsubscribedHandler,
        TLSVerification *Verification,
        TLSVerificationMode VerificationMode,
        DebugOutputTreshold DebugTreshold)
    :
        SelfHostedVerifier(new TLSVerification(VerificationMode)),
        ConnectionHandler(ConnectionHandler),
        StanzaHandler(StanzaHandler),
        DebugTreshold(DebugTreshold),
        CurrentAuthenticationState(AuthenticationState::None),
        Hostname(Hostname),
        Password(Password),
        Portnumber(Portnumber),
        MyJID(RequestedJID),
        Verification(Verification),
        VerificationMode(VerificationMode),
        Authentication(nullptr),
        SAXParser(nullptr)
    {
        Roster = new RosterMaintaner (Client,
               PresenceHandler,
               SubscribeHandler,
               SubscribedHandler,
               UnsubscribedHandler);

        //this->Password = Password;

        Reconnect();
    }

    void Connection::Connect()
    {
        DebugOut(DebugOutputTreshold::Debug)
                << "Starting io_service run in background thread"
                << std::endl;

        if( io_service != nullptr )
        {
            io_service->stop();
        }

        if( IOThread != nullptr )
        {
            IOThread->join();
        }

        io_service.reset( new boost::asio::io_service() );

        Client.reset(
                    new Network::AsyncTCPXMLClient (
                        io_service,
                        ((Verification != nullptr) ? Verification : SelfHostedVerifier.get()),
                        Hostname,
                        Portnumber,
                        boost::bind(&Connection::ClientDisconnected, this),
                        DebugTreshold ) );


        PreviouslyBroadcastedState = ConnectionCallback::ConnectionState::Connecting;
        //Client->Reset();
        if( !Client->ConnectSocket() )
        {
            CurrentConnectionState = ConnectionState::ErrorConnecting;
            std::cerr << "DXMPP: Failed to connect" << std::endl;
            BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorConnecting);
            return;
        }
        OpenXMPPStream();
        Client->AsyncRead();
        Roster->ResetClient(Client);

        SAXParser = xercesc::XMLReaderFactory::createXMLReader();
        SAXParser->setFeature(XMLUni::fgXercesSchema, false);   // optional
        SAXParser->setFeature(XMLUni::fgSAX2CoreValidation, false);

        SAXParser->setContentHandler(this);
        SAXParser->setErrorHandler(this);


        // Fork io
        IOThread.reset(
                    new boost::thread(boost::bind(
                                          &boost::asio::io_service::run,
                                          io_service.get())));

        Network::AsyncTCPXMLClientXercesInputWrapper Deluxe(Client.get());
        SAXParser->parse(Deluxe);
    }

    Connection::~Connection()
    {
        if( Authentication != nullptr )
            delete Authentication;
        delete Roster;

        DebugOut(DebugOutputTreshold::Debug) << "~Connection"  << std::endl;
    }

    static void InitXerces()
    {
        static bool InitiatedXerces = false;
        if( !InitiatedXerces )
        {
            XMLPlatformUtils::Initialize();
            InitiatedXerces = true;
        }
    }

    SharedConnection Connection::Create( const std::string &Hostname,
                                         int Portnumber,
                                         const JID &RequestedJID,
                                         const std::string &Password,
                                         IEventHandler* Handler,
                                         TLSVerification *Verification,
                                         DebugOutputTreshold DebugTreshold)
    {

        InitXerces();

        ConnectionCallback *ConnectionHandler = dynamic_cast<ConnectionCallback*>  (Handler);
        StanzaCallback *StanzaHandler = dynamic_cast<StanzaCallback*> (Handler);
        PresenceCallback *PresenceHandler = dynamic_cast<PresenceCallback*>(Handler);
        SubscribeCallback *SubscribeHandler = dynamic_cast<SubscribeCallback*>(Handler);
        SubscribedCallback *SubscribedHandler = dynamic_cast<SubscribedCallback*>(Handler);
        UnsubscribedCallback *UnsubscribedHandler = dynamic_cast<UnsubscribedCallback*>(Handler);


        return boost::shared_ptr<Connection>(
                    new Connection(Hostname,
                                   Portnumber,
                                   RequestedJID,
                                   Password,
                                   ConnectionHandler,
                                   StanzaHandler,
                                   PresenceHandler,
                                   SubscribeHandler,
                                   SubscribedHandler,
                                   UnsubscribedHandler,
                                   Verification,
                                   Verification->Mode,
                                   DebugTreshold) );
    }


    SharedConnection Connection::Create(const std::string &Hostname,
                                        int Portnumber,
                                        const JID &RequestedJID,
                                        const std::string &Password,
                                        IEventHandler* Handler,
                                        TLSVerificationMode VerificationMode,
                                        DebugOutputTreshold DebugTreshold)
    {
        InitXerces();
        ConnectionCallback *ConnectionHandler = dynamic_cast<ConnectionCallback*>  (Handler);
        StanzaCallback *StanzaHandler = dynamic_cast<StanzaCallback*> (Handler);
        PresenceCallback *PresenceHandler = dynamic_cast<PresenceCallback*>(Handler);
        SubscribeCallback *SubscribeHandler = dynamic_cast<SubscribeCallback*>(Handler);
        SubscribedCallback *SubscribedHandler = dynamic_cast<SubscribedCallback*>(Handler);
        UnsubscribedCallback *UnsubscribedHandler = dynamic_cast<UnsubscribedCallback*>(Handler);

        if( ConnectionHandler == nullptr)
            std::cerr << "ConnectionHandler is null" << std::endl;


        return boost::shared_ptr<Connection>(
                    new Connection(Hostname,
                                   Portnumber,
                                   RequestedJID,
                                   Password,
                                   ConnectionHandler,
                                   StanzaHandler,
                                   PresenceHandler,
                                   SubscribeHandler,
                                   SubscribedHandler,
                                   UnsubscribedHandler,
                                   nullptr,
                                   VerificationMode,
                                   DebugTreshold) );
    }

    void Connection::ClientDisconnected()
    {
        std::cerr << "Client disconnected." << std::endl;
        CurrentConnectionState  = ConnectionState::ErrorUnknown;
        BrodcastConnectionState(ConnectionCallback::ConnectionState::ErrorUnknown);
    }
    /*void Connection::ClientGotData()
    {
        CheckStreamForValidXML();
    }*/


}
