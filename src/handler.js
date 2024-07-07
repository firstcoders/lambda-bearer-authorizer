/**
 * Copyright (C) 2019-2023 First Coders LTD
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
import createHandler from '@firstcoders/service-libs/src/createHandler';
import createPolicy from '@firstcoders/service-libs/src/createPolicy';
import verifyAccessToken from '@firstcoders/service-libs/src/verifyAccessToken';
import logger from '@firstcoders/service-libs/src/logger';
import config from './config';

export default createHandler(async (event) => {
  logger.debug('Running with config', config);

  try {
    const token = event?.authorizationToken?.replace('Bearer ', '');
    if (!token) {
      logger.info('No bearer token found in request');
      throw new Error('No bearer token found in request');
    }

    const decoded = verifyAccessToken(token, config.swsSecret, {
      audience: config.jwtAudience,
      algorithms: config.jwtAllowedAlgorithms,
    });
    return createPolicy(event, 'Allow', decoded.sub, decoded);
  } catch (error) {
    return createPolicy(event, 'Deny');
  }
});
