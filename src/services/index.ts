import { TokenWeaverService } from './token-weaver.service';
import { loadTokenWeaverConfig } from '../config/token-weaver.config';

export const tokenWeaverService = new TokenWeaverService(loadTokenWeaverConfig());
