import React from 'react';
import { ApiScreen } from './ApiScreen';
import { MobileApi } from '../services/MobileApi';

export default function KYCStartScreen(): React.JSX.Element {
  return <ApiScreen
    title="KYC session"
    load={MobileApi.dashboard}
    actionLabel="Start KYC session"
    action={async () => {
      await MobileApi.createKycSession();
      return MobileApi.dashboard();
    }}
  />;
}
