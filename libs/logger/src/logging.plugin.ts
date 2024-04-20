import { ApolloServerPlugin, GraphQLRequestContext, GraphQLRequestListener } from '@apollo/server';
import { Plugin } from '@nestjs/apollo';

@Plugin()
export class LoggingPlugin implements ApolloServerPlugin {
    async requestDidStart(
        requestContext: GraphQLRequestContext<any>,
    ): Promise<GraphQLRequestListener<any>> {
        console.log('Request started');
        console.log(requestContext.request)
        return {
            async willSendResponse() {
                console.log('Will send response');
            },
        };
    }
}