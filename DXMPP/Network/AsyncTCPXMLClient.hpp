//
//  AsyncTCPXMLClient.hpp
//  DXMPP
//
//  Created by Stefan Karlsson 2014
//  Copyright (c) 2014 Deus ex Machinae. All rights reserved.
//

#ifndef DXMPP_AsyncTCPClient_hpp
#define DXMPP_AsyncTCPClient_hpp

#ifdef __APPLE__

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostics push
#pragma GCC diagnostics ignored "-Wdeprecated-declarations"
#endif // __clang__


#endif

#include <pugixml/pugixml.hpp>
#include <DXMPP/Debug/DebugOutputTreshold.hpp>
#include <DXMPP/TLSVerification.hpp>

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/smart_ptr.hpp>
#include <memory>
#include <sstream>
#include <queue>

#include <xercesc/util/BinInputStream.hpp>
#include <xercesc/sax/InputSource.hpp>


namespace DXMPP
{
    namespace Network
    {
        class AsyncTCPXMLClient :
                public xercesc::BinInputStream
        {
            TLSVerification *TLSConfig;
            DebugOutputTreshold DebugTreshold;

            static const int ReadDataBufferSize = 1024;
            char ReadDataBufferNonSSL[ReadDataBufferSize];
            std::stringstream ReadDataStreamNonSSL;

            std::queue<XMLByte> IncomingBuffer;

            char ReadDataBufferSSL[ReadDataBufferSize];
            std::stringstream ReadDataStreamSSL;

            boost::asio::mutable_buffers_1 SSLBuffer;
            boost::asio::mutable_buffers_1 NonSSLBuffer;
            void SendKeepAliveWhitespace();
            std::unique_ptr<boost::asio::deadline_timer>  SendKeepAliveWhitespaceTimer;
            std::string SendKeepAliveWhiteSpaceDataToSend;
            int SendKeepAliveWhiteSpaceTimeeoutSeconds;

            boost::asio::strand SynchronizationStrand;

            //boost::shared_mutex ReadMutex;
            //boost::shared_mutex WriteMutex;
            boost::posix_time::ptime LastWrite;

            //boost::shared_mutex IncomingDocumentsMutex;
            //std::queue<pugi::xml_document*> IncomingDocuments;

            std::queue<std::shared_ptr<std::string>> OutgoingData;
            boost::shared_mutex OutgoingDataMutex;
            bool Flushing;

            void FlushOutgoingDataUnsafe();

        public:

            // Start Xerces Bininput

            XMLFilePos 	curPos () const
            {
                return 1;
            }

            XMLSize_t readBytes (XMLByte *const toFill, const XMLSize_t maxToRead)
            {
                XMLSize_t Count= 0;

                for( ; Count < maxToRead && !IncomingBuffer.empty(); Count++ )
                {
                    XMLByte TData;
                    TData = IncomingBuffer.front();
                    IncomingBuffer.pop();
                    toFill[Count] = TData;
                }
                return Count;
            }

            const XMLCh * 	getContentType () const
            {
                return nullptr;
            }


            void FlushOutgoingData();

            void SignalError();
            std::stringstream *ReadDataStream;
            char * ReadDataBuffer;

            enum class ConnectionState
            {
                Connected,
                Upgrading,
                Disconnected,
                Error
            };

            std::string Hostname;
            int Portnumber;

            bool SSLConnection;
            volatile ConnectionState CurrentConnectionState;

            boost::shared_ptr<boost::asio::io_service> io_service;
            boost::scoped_ptr<boost::asio::ssl::context> ssl_context;
            boost::scoped_ptr<boost::asio::ip::tcp::socket> tcp_socket;
            boost::scoped_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&>> ssl_socket;


            void HandleWrite(boost::asio::ip::tcp::socket *active_socket,
                             std::shared_ptr<std::string> Data,
                             const boost::system::error_code &error);


            void SetKeepAliveByWhiteSpace(const std::string &DataToSend,
                                          int TimeoutSeconds = 5);
            bool EnsureTCPKeepAlive();
            bool ConnectTLSSocket();
            bool ConnectSocket();
            void AsyncRead();

            bool VerifyCertificate(bool preverified,
                                    boost::asio::ssl::verify_context& ctx);

            void WriteXMLToSocket(pugi::xml_document *Doc);
            void WriteTextToSocket(const std::string &Data);

            void HandleRead(
                            boost::asio::ip::tcp::socket *active_socket,
                            char *ActiveDataBuffer,
                            const boost::system::error_code &error,
                            std::size_t bytes_transferred);


            bool InnerLoadXML();
            void LoadXML();

            void ClearReadDataStream();

            void Reset();


            virtual ~AsyncTCPXMLClient()
            {
            }


            typedef boost::function<void (void)> ErrorCallbackFunction;

            ErrorCallbackFunction ErrorCallback;

            AsyncTCPXMLClient(
                               boost::shared_ptr<boost::asio::io_service> IOService,
                               TLSVerification *TLSConfig,
                               const std::string &Hostname,
                               int Portnumber,
                               const ErrorCallbackFunction &ErrorCallback,
                               DebugOutputTreshold DebugTreshold = DebugOutputTreshold::Error)
                :
                  TLSConfig(TLSConfig),
                  DebugTreshold(DebugTreshold),
                  SSLBuffer( boost::asio::buffer(ReadDataBufferSSL, ReadDataBufferSize) ),
                  NonSSLBuffer( boost::asio::buffer(ReadDataBufferNonSSL, ReadDataBufferSize) ),
                  SynchronizationStrand(*IOService),
                  ErrorCallback(ErrorCallback)

            {
                this->io_service = IOService;
                this->Hostname = Hostname;
                this->Portnumber = Portnumber;
                Flushing = false;
            }
        };

        class AsyncTCPXMLClientXercesInputWrapper:
                public xercesc::InputSource
        {
            AsyncTCPXMLClient *Client;
        public:

            AsyncTCPXMLClientXercesInputWrapper(AsyncTCPXMLClient *Client)
                :Client(Client)
            {
            }

            virtual ~AsyncTCPXMLClientXercesInputWrapper()
            {
            }

            xercesc::BinInputStream *makeStream() const
            {
                return Client;
            }

            const XMLCh * getEncoding() const
            {
                return nullptr;
            }

            const XMLCh * getPublicId()	const
            {
                return nullptr;
            }


            const XMLCh * getSystemId()const
            {
                return nullptr;
            }

            void setEncoding(const XMLCh *const encodingStr	)
            {
            }


            void setIssueFatalErrorIfNotFound(const bool flag)
            {
            }

            void setPublicId(const XMLCh *const publicId)
            {
            }

            void setSystemId(const XMLCh *const systemId)
            {
            }
        };
    }
}

#ifdef __APPLE__

#if defined(__clang__)
#pragma clang diagnostic pop

#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic pop
#endif // __clang__


#endif


#endif // DXMPP_AsyncTCPClient_hpp
