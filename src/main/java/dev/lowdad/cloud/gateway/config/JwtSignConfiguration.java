package dev.lowdad.cloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;

/**
 * <p>
 * jwt 配置
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/25
 */
@Component
@ConfigurationProperties("app.jwt")
@Data
@RefreshScope
public class JwtSignConfiguration {

    private String signKey;
}
