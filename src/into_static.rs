use roles_logic_sv2::parsers::{
    CommonMessages,
    JobDeclaration::{
        AllocateMiningJobToken, AllocateMiningJobTokenSuccess, DeclareMiningJob,
        DeclareMiningJobError, DeclareMiningJobSuccess, IdentifyTransactions,
        IdentifyTransactionsSuccess, ProvideMissingTransactions, ProvideMissingTransactionsSuccess,
        SubmitSolution,
    },
    TemplateDistribution::{self, CoinbaseOutputDataSize},
    PoolMessages,
};

pub fn into_static(m: PoolMessages<'_>) -> PoolMessages<'static> {
    match m {
        PoolMessages::Mining(m) => PoolMessages::Mining(m.into_static()),
        PoolMessages::Common(m) => match m {
            CommonMessages::ChannelEndpointChanged(m) => {
                PoolMessages::Common(CommonMessages::ChannelEndpointChanged(m.into_static()))
            }
            CommonMessages::SetupConnection(m) => {
                PoolMessages::Common(CommonMessages::SetupConnection(m.into_static()))
            }
            CommonMessages::SetupConnectionError(m) => {
                PoolMessages::Common(CommonMessages::SetupConnectionError(m.into_static()))
            }
            CommonMessages::SetupConnectionSuccess(m) => {
                PoolMessages::Common(CommonMessages::SetupConnectionSuccess(m.into_static()))
            }
        },
        PoolMessages::JobDeclaration(m) => match m {
            AllocateMiningJobToken(m) => {
                PoolMessages::JobDeclaration(AllocateMiningJobToken(m.into_static()))
            }
            AllocateMiningJobTokenSuccess(m) => {
                PoolMessages::JobDeclaration(AllocateMiningJobTokenSuccess(m.into_static()))
            }
            DeclareMiningJob(m) => PoolMessages::JobDeclaration(DeclareMiningJob(m.into_static())),
            DeclareMiningJobError(m) => {
                PoolMessages::JobDeclaration(DeclareMiningJobError(m.into_static()))
            }
            DeclareMiningJobSuccess(m) => {
                PoolMessages::JobDeclaration(DeclareMiningJobSuccess(m.into_static()))
            }
            IdentifyTransactions(m) => {
                PoolMessages::JobDeclaration(IdentifyTransactions(m.into_static()))
            }
            IdentifyTransactionsSuccess(m) => {
                PoolMessages::JobDeclaration(IdentifyTransactionsSuccess(m.into_static()))
            }
            ProvideMissingTransactions(m) => {
                PoolMessages::JobDeclaration(ProvideMissingTransactions(m.into_static()))
            }
            ProvideMissingTransactionsSuccess(m) => {
                PoolMessages::JobDeclaration(ProvideMissingTransactionsSuccess(m.into_static()))
            }
            SubmitSolution(m) => PoolMessages::JobDeclaration(SubmitSolution(m.into_static())),
        },
        PoolMessages::TemplateDistribution(m) => match m {
            CoinbaseOutputDataSize(m) => {
                PoolMessages::TemplateDistribution(CoinbaseOutputDataSize(m.into_static()))
            }
            TemplateDistribution::NewTemplate(m) => PoolMessages::TemplateDistribution(
                TemplateDistribution::NewTemplate(m.into_static()),
            ),
            TemplateDistribution::RequestTransactionData(m) => PoolMessages::TemplateDistribution(
                TemplateDistribution::RequestTransactionData(m.into_static()),
            ),
            TemplateDistribution::RequestTransactionDataError(m) => {
                PoolMessages::TemplateDistribution(
                    TemplateDistribution::RequestTransactionDataError(m.into_static()),
                )
            }
            TemplateDistribution::RequestTransactionDataSuccess(m) => {
                PoolMessages::TemplateDistribution(
                    TemplateDistribution::RequestTransactionDataSuccess(m.into_static()),
                )
            }
            TemplateDistribution::SetNewPrevHash(m) => PoolMessages::TemplateDistribution(
                TemplateDistribution::SetNewPrevHash(m.into_static()),
            ),
            TemplateDistribution::SubmitSolution(m) => PoolMessages::TemplateDistribution(
                TemplateDistribution::SubmitSolution(m.into_static()),
            ),
        },
    }
}
